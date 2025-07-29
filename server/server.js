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

// Trust proxy for Render deployment
app.set('trust proxy', 1);

const isProduction = process.env.NODE_ENV === 'production' || process.env.RENDER === 'true';

// CORS configuration - Simplified for same-domain hosting on Render
app.use(cors({
  origin: function(origin, callback) {
    // Allow requests from your Render domains and localhost for development
    const allowedOrigins = [
      'https://github-activity-frontend.onrender.com', // Your frontend Render URL
      'https://github-activity-frontend.onrender.com/api/user', // Your frontend Render URL
      'https://github-activity.onrender.com', // Same domain requests
      'http://localhost:5173',
      'http://localhost:3000'
    ];
    
    // Allow requests with no origin (same domain, mobile apps, etc.)
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.log('Blocked by CORS:', origin);
      callback(new Error('Not allowed by CORS'), false);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  optionsSuccessStatus: 200
}));

// Handle preflight requests
// app.options('*', cors());

app.use(express.json());

// Session configuration - Optimized for Render same-domain hosting
app.use(session({
  secret: process.env.SESSION_SECRET || 'github-activity-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    touchAfter: 24 * 3600,
    ttl: 7 * 24 * 60 * 60 // 7 days TTL
  }),
  cookie: {
    httpOnly: true,
    secure: isProduction, // HTTPS in production
    sameSite: 'lax', // Use 'lax' for same-domain hosting
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    domain: undefined // Let browser handle domain automatically
  },
  name: 'github.session',
  rolling: true, // Reset expiry on each request
  proxy: true // Trust proxy for secure cookies
}));

app.use(passport.initialize());
app.use(passport.session());

// Enhanced debug middleware
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path}`);
  console.log('Origin:', req.get('Origin'));
  console.log('Referer:', req.get('Referer'));
  console.log('Session ID:', req.sessionID);
  console.log('Session exists:', !!req.session);
  console.log('User in session:', !!req.session?.passport?.user);
  console.log('Is Authenticated:', req.isAuthenticated());
  console.log('Cookie header:', req.headers.cookie);
  console.log('Session cookie config:', {
    secure: req.sessionStore?.cookie?.secure,
    sameSite: req.sessionStore?.cookie?.sameSite,
    domain: req.sessionStore?.cookie?.domain
  });
  console.log('---');
  next();
});

// MongoDB connection
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

// GitHub Strategy - Fixed
passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: process.env.GITHUB_CALLBACK_URL
}, async (accessToken, refreshToken, profile, done) => {
  try {
    console.log('GitHub Strategy called for user:', profile.username);
    
    let user = await User.findOne({ githubId: profile.id });
    
    if (user) {
      console.log('Existing user found:', user.username);
      user.accessToken = accessToken;
      user.avatar = profile.photos[0]?.value;
      user.displayName = profile.displayName;
      await user.save();
      return done(null, user);
    }
    
    console.log('Creating new user:', profile.username);
    user = new User({
      githubId: profile.id,
      username: profile.username,
      displayName: profile.displayName || profile.username,
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
  console.log('Serializing user:', user._id);
  done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
  try {
    console.log('Deserializing user ID:', id);
    const user = await User.findById(id);
    if (!user) {
      console.log('User not found during deserialization');
      return done(null, false);
    }
    console.log('User deserialized:', user.username);
    done(null, user);
  } catch (error) {
    console.error('Deserialize user error:', error);
    done(error, null);
  }
});

// Enhanced auth middleware with better error handling
const requireAuth = (req, res, next) => {
  console.log('Auth check - Session:', !!req.session);
  console.log('Auth check - User:', !!req.user);
  console.log('Auth check - Authenticated:', req.isAuthenticated());
  console.log('Auth check - Session passport:', req.session?.passport);
  
  if (req.isAuthenticated() && req.user) {
    return next();
  }
  
  console.log('Authentication failed');
  res.status(401).json({ 
    error: 'Authentication required',
    message: 'Please login with GitHub to access this resource',
    debug: {
      hasSession: !!req.session,
      hasUser: !!req.user,
      isAuthenticated: req.isAuthenticated(),
      sessionID: req.sessionID,
      passportSession: req.session?.passport
    }
  });
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
      timeout: 15000
    });
    return response.data;
  } catch (error) {
    if (error.response?.status === 401) {
      console.error('GitHub token expired or invalid');
    } else if (error.response?.status === 403) {
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

// Health check endpoint - enhanced with session info
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    environment: process.env.NODE_ENV || 'development',
    session: {
      configured: !!req.sessionStore,
      hasSession: !!req.session,
      sessionID: req.sessionID
    }
  });
});

// Auth routes - Fixed callback handling
app.get('/auth/github', (req, res, next) => {
  console.log('Starting GitHub auth flow');
  // Store the origin for later redirect
  if (req.get('Referer')) {
    req.session.authOrigin = req.get('Referer');
  }
  passport.authenticate('github', { scope: ['user', 'repo'] })(req, res, next);
});

app.get('/auth/github/callback',
  passport.authenticate('github', { 
    failureRedirect: `${process.env.CLIENT_URL}?error=auth_failed` 
  }),
  (req, res) => {
    console.log('GitHub callback successful for user:', req.user?.username);
    console.log('Session after auth:', req.sessionID);
    console.log('Session user:', req.session?.passport);
    
    // Save session explicitly before redirect
    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
      }
      console.log('Session saved, redirecting to client');
      res.redirect(process.env.CLIENT_URL);
    });
  }
);

app.post('/auth/logout', (req, res) => {
  console.log('Logout requested for user:', req.user?.username);
  req.logout((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ error: 'Logout failed' });
    }
    req.session.destroy((err) => {
      if (err) {
        console.error('Session destroy error:', err);
      }
      res.clearCookie('github.session', {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'lax',
        domain: undefined
      });
      res.json({ message: 'Logged out successfully' });
    });
  });
});

// Debug session endpoint - enhanced
app.get('/api/session', (req, res) => {
  res.json({
    sessionID: req.sessionID,
    hasSession: !!req.session,
    hasUser: !!req.user,
    isAuthenticated: req.isAuthenticated(),
    passportSession: req.session?.passport,
    sessionCookie: req.session?.cookie,
    headers: {
      origin: req.get('Origin'),
      referer: req.get('Referer'),
      userAgent: req.get('User-Agent'),
      cookie: req.headers.cookie ? 'present' : 'missing'
    },
    user: req.user ? {
      id: req.user._id,
      username: req.user.username,
      displayName: req.user.displayName
    } : null
  });
});

// Test endpoint to verify cookie handling
app.get('/api/test-cookies', (req, res) => {
  // Set a test cookie with the same settings as session cookie
  res.cookie('test-cookie', 'test-value', {
    httpOnly: false, // Allow JS access for testing
    secure: isProduction,
    sameSite: 'lax',
    maxAge: 60000, // 1 minute
    domain: undefined
  });
  
  res.json({
    message: 'Test cookie set',
    receivedCookies: req.headers.cookie || 'No cookies received',
    sessionId: req.sessionID,
    hasSession: !!req.session,
    cookieConfig: {
      secure: isProduction,
      sameSite: 'lax',
      domain: 'undefined (let browser handle)'
    }
  });
});

// API routes
app.get('/api/user', requireAuth, (req, res) => {
  console.log('User API called for:', req.user.username);
  res.json({
    id: req.user._id,
    username: req.user.username,
    displayName: req.user.displayName,
    avatar: req.user.avatar
  });
});

// Main activity route
app.get('/api/activity/:date', requireAuth, async (req, res) => {
  try {
    const { date } = req.params;
    const selectedDate = new Date(date);
    const nextDate = getNextDay(selectedDate);

    if (isNaN(selectedDate.getTime())) {
      return res.status(400).json({ error: 'Invalid date format' });
    }

    console.log(`Fetching activity for ${req.user.username} on ${date}`);

    const since = selectedDate.toISOString();
    const until = nextDate.toISOString();

    const commits = [];
    const pullRequests = [];

    // Verify GitHub token is still valid
    try {
      await getGitHubData('https://api.github.com/user', req.user.accessToken);
    } catch (error) {
      if (error.response?.status === 401) {
        return res.status(401).json({ 
          error: 'GitHub token expired. Please login again.',
          reauth: true 
        });
      }
    }

    const repos = await getGitHubData(
      `https://api.github.com/user/repos?sort=updated&per_page=100&affiliation=owner,collaborator`,
      req.user.accessToken
    );

    console.log(`Found ${repos.length} repositories`);

    await pMap(
      repos.filter(repo => {
        const pushedAt = new Date(repo.pushed_at);
        const daysBetween = Math.abs(selectedDate - pushedAt) / (1000 * 60 * 60 * 24);
        return daysBetween <= 30;
      }),
      async (repo) => {
        try {
          const [repoCommits, repoPRs] = await Promise.all([
            getGitHubData(
              `https://api.github.com/repos/${repo.full_name}/commits?author=${req.user.username}&since=${since}&until=${until}&per_page=100`,
              req.user.accessToken
            ).catch(() => []),
            getGitHubData(
              `https://api.github.com/repos/${repo.full_name}/pulls?state=all&sort=updated&direction=desc&per_page=100`,
              req.user.accessToken
            ).catch(() => [])
          ]);

          for (const commit of repoCommits) {
            const stats = await getCommitDetails(repo.full_name, commit.sha, req.user.accessToken);
            commits.push({
              id: commit.sha,
              message: commit.commit.message.split('\n')[0],
              repository: repo.name,
              repositoryUrl: repo.html_url,
              url: commit.html_url,
              date: commit.commit.author.date,
              additions: stats.additions,
              deletions: stats.deletions
            });
          }

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
        }
      },
      { concurrency: 2 }
    );

    commits.sort((a, b) => new Date(b.date) - new Date(a.date));
    pullRequests.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    const summary = {
      totalCommits: commits.length,
      totalPullRequests: pullRequests.length,
      totalAdditions: commits.reduce((sum, c) => sum + (c.additions || 0), 0),
      totalDeletions: commits.reduce((sum, c) => sum + (c.deletions || 0), 0)
    };

    console.log(`Activity summary: ${summary.totalCommits} commits, ${summary.totalPullRequests} PRs`);

    res.json({
      date: formatDateForGitHub(selectedDate),
      commits,
      pullRequests,
      summary
    });

  } catch (error) {
    console.error('Error fetching activity:', error);
    
    if (error.response?.status === 401) {
      return res.status(401).json({ 
        error: 'GitHub authentication expired. Please login again.',
        reauth: true
      });
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

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    details: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Client URL: ${process.env.CLIENT_URL}`);
  console.log(`Callback URL: ${process.env.GITHUB_CALLBACK_URL}`);
  console.log(`Production mode: ${isProduction}`);
  console.log(`Session config: secure=${isProduction}, sameSite='lax'`);
});