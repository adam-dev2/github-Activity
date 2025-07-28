const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const GitHubStrategy = require('passport-github2').Strategy;
const session = require('express-session');
const MongoStore = require('connect-mongo');
const cors = require('cors');
const axios = require('axios');
const pMap = require('p-map');
require('dotenv').config();

const app = express();

// CORS configuration - more permissive for production debugging
app.use(cors({
  origin: true, // Allow all origins temporarily
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  optionsSuccessStatus: 200
}));

app.use(express.json());

// Handle preflight requests
app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin);
  res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Content-Length, X-Requested-With');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.sendStatus(200);
});

// Session configuration - dynamic based on environment
const isProduction = process.env.NODE_ENV === 'production';

app.use(session({
  secret: process.env.SESSION_SECRET || 'github-activity-secret',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI
  }),
  cookie: {
    httpOnly: true,
    secure: isProduction, // true for HTTPS in production, false for localhost
    sameSite: isProduction ? 'none' : 'lax', // 'none' for cross-origin in production
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    domain: isProduction ? undefined : undefined // Let browser handle domain
  },
  name: 'connect.sid'
}));

app.use(passport.initialize());
app.use(passport.session());

// Debug middleware (remove in production)
app.use((req, res, next) => {
  console.log('Is Authenticated:', req.isAuthenticated());
  next();
});

// MongoDB connection - removed hardcoded fallback
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

// User schema
const userSchema = new mongoose.Schema({
  githubId: String,
  username: String,
  displayName: String,
  avatar: String,
  accessToken: String
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// GitHub Strategy - using environment variables
passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: process.env.GITHUB_CALLBACK_URL
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ githubId: profile.id });
    
    if (user) {
      user.accessToken = accessToken;
      await user.save();
      return done(null, user);
    }
    
    user = new User({
      githubId: profile.id,
      username: profile.username,
      displayName: profile.displayName,
      avatar: profile.photos[0]?.value,
      accessToken: accessToken
    });
    
    await user.save();
    done(null, user);
  } catch (error) {
    console.error('GitHub Strategy error:', error);
    done(error, null);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    if (!user) {
      return done(null, false);
    }
    done(null, user);
  } catch (error) {
    console.error('Deserialize user error:', error);
    done(error, null);
  }
});

// Auth middleware
const requireAuth = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ error: 'Authentication required' });
};

// GitHub API helper function
const getGitHubData = async (url, token) => {
  try {
    const response = await axios.get(url, {
      headers: {
        'Authorization': `token ${token}`,
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'GitHub-Activity-Tracker'
      },
      timeout: 10000 // 10 second timeout
    });
    return response.data;
  } catch (error) {
    if (error.response?.status === 403) {
      console.warn('GitHub API rate limit or forbidden:', error.response?.data);
    } else {
      console.error('GitHub API error:', error.response?.data || error.message);
    }
    throw error;
  }
};

// Helper function to get commit details with stats
const getCommitDetails = async (repoFullName, sha, token) => {
  try {
    const commit = await getGitHubData(
      `https://api.github.com/repos/${repoFullName}/commits/${sha}`,
      token
    );
    return {
      additions: commit.stats?.additions || 0,
      deletions: commit.stats?.deletions || 0
    };
  } catch (error) {
    console.warn(`Failed to get commit details for ${sha}:`, error.message);
    return { additions: 0, deletions: 0 };
  }
};

// Date helper functions
const formatDateForGitHub = (date) => {
  return date.toISOString().split('T')[0];
};

const getNextDay = (date) => {
  const nextDay = new Date(date);
  nextDay.setDate(nextDay.getDate() + 1);
  return nextDay;
};

// Auth routes
app.get('/auth/github', passport.authenticate('github', { scope: ['user', 'repo'] }));

app.get('/auth/github/callback',
  passport.authenticate('github', { failureRedirect: process.env.CLIENT_URL }),
  (req, res) => {
    res.redirect(process.env.CLIENT_URL);
  }
);

app.post('/auth/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ error: 'Logout failed' });
    }
    req.session.destroy((err) => {
      if (err) {
        console.error('Session destroy error:', err);
      }
      res.clearCookie('connect.sid');
      res.json({ message: 'Logged out successfully' });
    });
  });
});

// API routes
app.get('/api/user', requireAuth, (req, res) => {
  res.json({
    id: req.user._id,
    username: req.user.username,
    displayName: req.user.displayName,
    avatar: req.user.avatar
  });
});

// Main activity route - improved with better error handling
app.get('/api/activity/:date', requireAuth, async (req, res) => {
  try {
    const { date } = req.params;
    const selectedDate = new Date(date);
    const nextDate = getNextDay(selectedDate);

    // Validate date
    if (isNaN(selectedDate.getTime())) {
      return res.status(400).json({ error: 'Invalid date format' });
    }

    const since = selectedDate.toISOString();
    const until = nextDate.toISOString();

    const commits = [];
    const pullRequests = [];

    // Get user's repositories
    const repos = await getGitHubData(
      `https://api.github.com/user/repos?sort=updated&per_page=100&affiliation=owner,collaborator`,
      req.user.accessToken
    );

    // Process repositories with concurrency control
    await pMap(
      repos.filter(repo => {
        // Only check repos updated recently to reduce API calls
        const pushedAt = new Date(repo.pushed_at);
        const daysBetween = Math.abs(selectedDate - pushedAt) / (1000 * 60 * 60 * 24);
        return daysBetween <= 30; // Only check repos updated in last 30 days
      }),
      async (repo) => {
        try {
          // Get commits and PRs in parallel
          const [repoCommits, repoPRs] = await Promise.all([
            getGitHubData(
              `https://api.github.com/repos/${repo.full_name}/commits?author=${req.user.username}&since=${since}&until=${until}&per_page=100`,
              req.user.accessToken
            ).catch(() => []), // Return empty array on error
            getGitHubData(
              `https://api.github.com/repos/${repo.full_name}/pulls?state=all&sort=updated&direction=desc&per_page=100`,
              req.user.accessToken
            ).catch(() => []) // Return empty array on error
          ]);

          // Process commits with detailed stats
          for (const commit of repoCommits) {
            const stats = await getCommitDetails(repo.full_name, commit.sha, req.user.accessToken);
            commits.push({
              id: commit.sha,
              message: commit.commit.message.split('\n')[0], // First line only
              repository: repo.name,
              repositoryUrl: repo.html_url,
              url: commit.html_url,
              date: commit.commit.author.date,
              additions: stats.additions,
              deletions: stats.deletions
            });
          }

          // Process pull requests
          repoPRs.forEach(pr => {
            const prDate = new Date(pr.created_at);
            if (
              prDate >= selectedDate &&
              prDate < nextDate &&
              pr.user.login === req.user.username
            ) {
              pullRequests.push({
                id: pr.id,
                title: pr.title,
                number: pr.number,
                repository: repo.name,
                repositoryUrl: repo.html_url,
                url: pr.html_url,
                state: pr.state,
                createdAt: pr.created_at,
                updatedAt: pr.updated_at
              });
            }
          });

        } catch (repoError) {
          console.warn(`Skipping repo ${repo.name}:`, repoError.message);
          // Continue processing other repos
        }
      },
      { concurrency: 3 } // Reduced concurrency to avoid rate limits
    );

    // Sort results
    commits.sort((a, b) => new Date(b.date) - new Date(a.date));
    pullRequests.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    // Calculate summary
    const summary = {
      totalCommits: commits.length,
      totalPullRequests: pullRequests.length,
      totalAdditions: commits.reduce((sum, c) => sum + (c.additions || 0), 0),
      totalDeletions: commits.reduce((sum, c) => sum + (c.deletions || 0), 0)
    };

    res.json({
      date: formatDateForGitHub(selectedDate),
      commits,
      pullRequests,
      summary
    });

  } catch (error) {
    console.error('Error fetching activity:', error);
    
    // Handle specific error types
    if (error.response?.status === 401) {
      return res.status(401).json({ error: 'GitHub authentication expired. Please login again.' });
    }
    
    if (error.response?.status === 403) {
      return res.status(429).json({ error: 'GitHub API rate limit exceeded. Please try again later.' });
    }
    
    res.status(500).json({ 
      error: 'Failed to fetch GitHub activity',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    details: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// 404 handler - must be last
app.all('*', (req, res) => {
  res.status(404).json({ error: `Route ${req.method} ${req.path} not found` });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});