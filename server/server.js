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

app.use(cors({
  origin: 'https://github-activity-silk.vercel.app',
  credentials: true
}));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'github-activity-secret',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI
  }),
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 24 * 60 * 60 * 1000
  }

}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://adam222xyz:PbauxEHjkDWW7tT1@cluster0.i2sgm7s.mongodb.net/')
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

const userSchema = new mongoose.Schema({
  githubId: String,
  username: String,
  displayName: String,
  avatar: String,
  accessToken: String
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

passport.use(new GitHubStrategy({
  clientID: 'Ov23li8HYM45WhtRfpeA',
  clientSecret: '519e59b772a4d35d6c4326e9b13a5847e2e0d8c6',
  callbackURL: 'https://github-activity.onrender.com/auth/github/callback'
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
    done(error, null);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

const requireAuth = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ error: 'Authentication required' });
};

app.get('/auth/github', passport.authenticate('github', { scope: ['user', 'repo'] }));

app.get('/auth/github/callback',
  passport.authenticate('github', { failureRedirect: 'https://github-activity-silk.vercel.app' }),
  (req, res) => {
    res.redirect('https://github-activity-silk.vercel.app');
  }
);

app.post('/auth/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.json({ message: 'Logged out successfully' });
  });
});

app.get('/api/user', requireAuth, (req, res) => {
  res.json({
    id: req.user._id,
    username: req.user.username,
    displayName: req.user.displayName,
    avatar: req.user.avatar
  });
});

const getGitHubData = async (url, token) => {
  try {
    const response = await axios.get(url, {
      headers: {
        'Authorization': `token ${token}`,
        'Accept': 'application/vnd.github.v3+json'
      }
    });
    return response.data;
  } catch (error) {
    console.error('GitHub API error:', error.response?.data || error.message);
    throw error;
  }
};

const formatDateForGitHub = (date) => {
  return date.toISOString().split('T')[0];
};

const getNextDay = (date) => {
  const nextDay = new Date(date);
  nextDay.setDate(nextDay.getDate() + 1);
  return nextDay;
};

app.get('/api/activity/:date', requireAuth, async (req, res) => {
  try {
    const { date } = req.params;
    const selectedDate = new Date(date);
    const nextDate = getNextDay(selectedDate);

    const since = selectedDate.toISOString();
    const until = nextDate.toISOString();

    const commits = [];
    const pullRequests = [];

    const repos = await getGitHubData(
      `https://api.github.com/user/repos?sort=updated&per_page=100`,
      req.user.accessToken
    );

    await pMap(
      repos,
      async (repo) => {
        try {
          const pushedAt = new Date(repo.pushed_at);
          if (pushedAt < selectedDate) return;

          const [repoCommits, repoPRs] = await Promise.all([
            getGitHubData(
              `https://api.github.com/repos/${repo.full_name}/commits?author=${req.user.username}&since=${since}&until=${until}`,
              req.user.accessToken
            ),
            getGitHubData(
              `https://api.github.com/repos/${repo.full_name}/pulls?state=all&sort=updated&direction=desc`,
              req.user.accessToken
            )
          ]);

          repoCommits.forEach(commit => {
            commits.push({
              id: commit.sha,
              message: commit.commit.message,
              repository: repo.name,
              repositoryUrl: repo.html_url,
              url: commit.html_url,
              date: commit.commit.author.date,
              additions: commit.stats?.additions || 0,
              deletions: commit.stats?.deletions || 0
            });
          });

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
          console.log(`Skipping repo ${repo.name}:`, repoError.message);
        }
      },
      { concurrency: 5 } 
    );

    commits.sort((a, b) => new Date(b.date) - new Date(a.date));
    pullRequests.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    res.json({
      date: formatDateForGitHub(selectedDate),
      commits,
      pullRequests,
      summary: {
        totalCommits: commits.length,
        totalPullRequests: pullRequests.length,
        totalAdditions: commits.reduce((sum, c) => sum + c.additions, 0),
        totalDeletions: commits.reduce((sum, c) => sum + c.deletions, 0)
      }
    });

  } catch (error) {
    console.error('Error fetching activity:', error);
    res.status(500).json({ error: 'Failed to fetch GitHub activity' });
  }
});

// app.get('/api/activity/:date', requireAuth, async (req, res) => {
//   try {
//     const { date } = req.params;
//     const selectedDate = new Date(date);
//     const nextDate = getNextDay(selectedDate);
    
//     const since = selectedDate.toISOString();
//     const until = nextDate.toISOString();
    
//     // Get user's repositories
//     const repos = await getGitHubData(
//       `https://api.github.com/user/repos?sort=updated&per_page=100`,
//       req.user.accessToken
//     );
    
//     const commits = [];
//     const pullRequests = [];
    
//     // Get commits for each repository
//     for (const repo of repos) {
//       try {
//         // Get commits by the authenticated user for the selected date
//         const repoCommits = await getGitHubData(
//           `https://api.github.com/repos/${repo.full_name}/commits?author=${req.user.username}&since=${since}&until=${until}`,
//           req.user.accessToken
//         );
        
//         repoCommits.forEach(commit => {
//           commits.push({
//             id: commit.sha,
//             message: commit.commit.message,
//             repository: repo.name,
//             repositoryUrl: repo.html_url,
//             url: commit.html_url,
//             date: commit.commit.author.date,
//             additions: commit.stats?.additions || 0,
//             deletions: commit.stats?.deletions || 0
//           });
//         });
        
//         // Get pull requests for the selected date
//         const repoPRs = await getGitHubData(
//           `https://api.github.com/repos/${repo.full_name}/pulls?state=all&sort=updated&direction=desc`,
//           req.user.accessToken
//         );
        
//         repoPRs.forEach(pr => {
//           const prDate = new Date(pr.created_at);
//           if (prDate >= selectedDate && prDate < nextDate && pr.user.login === req.user.username) {
//             pullRequests.push({
//               id: pr.id,
//               title: pr.title,
//               number: pr.number,
//               repository: repo.name,
//               repositoryUrl: repo.html_url,
//               url: pr.html_url,
//               state: pr.state,
//               createdAt: pr.created_at,
//               updatedAt: pr.updated_at
//             });
//           }
//         });
        
//       } catch (repoError) {
//         // Skip repositories that can't be accessed
//         console.log(`Skipping repository ${repo.name}:`, repoError.message);
//         continue;
//       }
//     }
    
//     // Sort by date (newest first)
//     commits.sort((a, b) => new Date(b.date) - new Date(a.date));
//     pullRequests.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    
//     res.json({
//       date: formatDateForGitHub(selectedDate),
//       commits,
//       pullRequests,
//       summary: {
//         totalCommits: commits.length,
//         totalPullRequests: pullRequests.length,
//         totalAdditions: commits.reduce((sum, c) => sum + c.additions, 0),
//         totalDeletions: commits.reduce((sum, c) => sum + c.deletions, 0)
//       }
//     });
    
//   } catch (error) {
//     console.error('Error fetching activity:', error);
//     res.status(500).json({ error: 'Failed to fetch GitHub activity' });
//   }
// });

const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});