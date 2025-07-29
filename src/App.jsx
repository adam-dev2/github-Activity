import React, { useState, useEffect } from 'react';
import { Calendar, Github, GitCommit, GitPullRequest, User, LogOut, Activity, Plus, Minus } from 'lucide-react';

const API_BASE = 'https://github-activity.onrender.com';

const App = () => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activity, setActivity] = useState(null);
  const [selectedDate, setSelectedDate] = useState(new Date().toISOString().split('T')[0]);
  const [loadingActivity, setLoadingActivity] = useState(false);
  const [authError, setAuthError] = useState(null);

  useEffect(() => {
    checkAuthStatus();
  }, []);

  useEffect(() => {
    if (user) {
      fetchActivity(selectedDate);
    }
  }, [user, selectedDate]);

  const checkAuthStatus = async () => {
    try {
      console.log('Checking auth status...');
      const response = await fetch(`${API_BASE}/api/user`, {
        method: 'GET',
        credentials: 'include',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const userData = await response.json();
        console.log('User authenticated:', userData.username);
        setUser(userData);
        setAuthError(null);
      } else {
        console.log('Not authenticated, response status:', response.status);
        const errorData = await response.json().catch(() => ({}));
        console.log('Auth error details:', errorData);
        setAuthError(errorData.error || 'Authentication failed');
      }
    } catch (error) {
      console.error('Auth check failed:', error);
      setAuthError('Failed to check authentication status');
    } finally {
      setLoading(false);
    }
  };

  const fetchActivity = async (date) => {
    setLoadingActivity(true);
    try {
      console.log('Fetching activity for date:', date);
      const response = await fetch(`${API_BASE}/api/activity/${date}`, {
        method: 'GET',
        credentials: 'include',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        }
      });
      
      if (response.ok) {
        const activityData = await response.json();
        console.log('Activity fetched successfully');
        setActivity(activityData);
      } else if (response.status === 401) {
        console.log('Authentication expired, redirecting to login');
        const errorData = await response.json().catch(() => ({}));
        if (errorData.reauth) {
          setUser(null);
          setAuthError('Your session has expired. Please login again.');
        }
      } else {
        console.error('Failed to fetch activity, status:', response.status);
        const errorData = await response.json().catch(() => ({}));
        console.error('Activity error details:', errorData);
      }
    } catch (error) {
      console.error('Error fetching activity:', error);
    } finally {
      setLoadingActivity(false);
    }
  };

  const handleLogin = () => {
    console.log('Initiating login...');
    const currentUrl = window.location.href;
    localStorage.setItem('preAuthUrl', currentUrl);
    
    window.location.href = `${API_BASE}/auth/github`;
  };

  const handleLogout = async () => {
    try {
      console.log('Logging out...');
      const response = await fetch(`${API_BASE}/auth/logout`, {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        }
      });
      
      if (response.ok) {
        console.log('Logout successful');
        setUser(null);
        setActivity(null);
        setAuthError(null);
      } else {
        console.error('Logout failed');
      }
    } catch (error) {
      console.error('Logout error:', error);
    }
  };

  const getQuickDateOption = (option) => {
    const today = new Date();
    switch (option) {
      case 'today':
        return today.toISOString().split('T')[0];
      case 'yesterday':
        const yesterday = new Date(today);
        yesterday.setDate(yesterday.getDate() - 1);
        return yesterday.toISOString().split('T')[0];
      default:
        return today.toISOString().split('T')[0];
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });
  };

  const formatTime = (dateString) => {
    return new Date(dateString).toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const checkSession = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/session`, {
        credentials: 'include'
      });
      const sessionData = await response.json();
      console.log('Session debug info:', sessionData);
    } catch (error) {
      console.error('Session check failed:', error);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900 mx-auto mb-4"></div>
          <p className="text-gray-600">Checking authentication...</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 to-gray-800 flex items-center justify-center">
        <div className="bg-white rounded-lg shadow-xl p-8 max-w-md w-full mx-4">
          <div className="text-center">
            <Github className="h-16 w-16 text-gray-900 mx-auto mb-6" />
            <h1 className="text-2xl font-bold text-gray-900 mb-2">GitHub Activity Tracker</h1>
            <p className="text-gray-600 mb-4">Track your daily commits and pull requests</p>
            
            {authError && (
              <div className="bg-red-50 border border-red-200 rounded-md p-3 mb-6">
                <p className="text-red-600 text-sm">{authError}</p>
              </div>
            )}
            
            <button
              onClick={handleLogin}
              className="w-full bg-gray-900 text-white py-3 px-4 rounded-lg hover:bg-gray-800 transition-colors flex items-center justify-center gap-2 mb-4"
            >
              <Github className="h-5 w-5" />
              Sign in with GitHub
            </button>
            
            <button
              onClick={checkSession}
              className="text-xs text-gray-500 hover:text-gray-700"
            >
              Debug: Check Session
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center gap-3">
              <Activity className="h-8 w-8 text-gray-900" />
              <h1 className="text-xl font-semibold text-gray-900">GitHub Activity</h1>
            </div>
            
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <img
                  src={user.avatar}
                  alt={user.displayName}
                  className="h-8 w-8 rounded-full"
                />
                <span className="text-sm font-medium text-gray-700">{user.displayName}</span>
              </div>
              <button
                onClick={handleLogout}
                className="text-gray-500 hover:text-gray-700 transition-colors"
                title="Logout"
              >
                <LogOut className="h-5 w-5" />
              </button>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="bg-white rounded-lg shadow-sm border p-6 mb-6">
          <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center">
            <div className="flex items-center gap-2">
              <Calendar className="h-5 w-5 text-gray-500" />
              <label className="text-sm font-medium text-gray-700">Select Date:</label>
            </div>
            
            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => setSelectedDate(getQuickDateOption('today'))}
                className={`px-3 py-1 rounded-md text-sm font-medium transition-colors ${
                  selectedDate === getQuickDateOption('today')
                    ? 'bg-gray-900 text-white'
                    : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                }`}
              >
                Today
              </button>
              <button
                onClick={() => setSelectedDate(getQuickDateOption('yesterday'))}
                className={`px-3 py-1 rounded-md text-sm font-medium transition-colors ${
                  selectedDate === getQuickDateOption('yesterday')
                    ? 'bg-gray-900 text-white'
                    : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                }`}
              >
                Yesterday
              </button>
              <input
                type="date"
                value={selectedDate}
                onChange={(e) => setSelectedDate(e.target.value)}
                className="px-3 py-1 border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-gray-900 focus:border-transparent"
              />
            </div>
          </div>
        </div>

        {loadingActivity ? (
          <div className="bg-white rounded-lg shadow-sm border p-12">
            <div className="flex items-center justify-center">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900"></div>
              <span className="ml-3 text-gray-600">Loading activity...</span>
            </div>
          </div>
        ) : activity ? (
          <div className="space-y-6">
            <div className="bg-white rounded-lg shadow-sm border p-6">
              <h2 className="text-lg font-semibold text-gray-900 mb-4">
                Activity for {formatDate(activity.date)}
              </h2>
              
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-gray-900">{activity.summary.totalCommits}</div>
                  <div className="text-sm text-gray-500">Commits</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-gray-900">{activity.summary.totalPullRequests}</div>
                  <div className="text-sm text-gray-500">Pull Requests</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-green-600">+{activity.summary.totalAdditions}</div>
                  <div className="text-sm text-gray-500">Lines Added</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-red-600">-{activity.summary.totalDeletions}</div>
                  <div className="text-sm text-gray-500">Lines Deleted</div>
                </div>
              </div>
            </div>

            {activity.commits.length > 0 && (
              <div className="bg-white rounded-lg shadow-sm border">
                <div className="p-6 border-b">
                  <h3 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
                    <GitCommit className="h-5 w-5" />
                    Commits ({activity.commits.length})
                  </h3>
                </div>
                <div className="divide-y">
                  {activity.commits.map((commit) => (
                    <div key={commit.id} className="p-6">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <p className="text-gray-900 font-medium mb-2">{commit.message}</p>
                          <div className="flex items-center gap-4 text-sm text-gray-500">
                            <span className="flex items-center gap-1">
                              <Github className="h-4 w-4" />
                              {commit.repository}
                            </span>
                            <span>{formatTime(commit.date)}</span>
                            {commit.additions > 0 && (
                              <span className="flex items-center gap-1 text-green-600">
                                <Plus className="h-3 w-3" />
                                {commit.additions}
                              </span>
                            )}
                            {commit.deletions > 0 && (
                              <span className="flex items-center gap-1 text-red-600">
                                <Minus className="h-3 w-3" />
                                {commit.deletions}
                              </span>
                            )}
                          </div>
                        </div>
                        <a
                          href={commit.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-gray-400 hover:text-gray-600 transition-colors"
                        >
                          <Github className="h-5 w-5" />
                        </a>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {activity.pullRequests.length > 0 && (
              <div className="bg-white rounded-lg shadow-sm border">
                <div className="p-6 border-b">
                  <h3 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
                    <GitPullRequest className="h-5 w-5" />
                    Pull Requests ({activity.pullRequests.length})
                  </h3>
                </div>
                <div className="divide-y">
                  {activity.pullRequests.map((pr) => (
                    <div key={pr.id} className="p-6">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <p className="text-gray-900 font-medium mb-2">{pr.title}</p>
                          <div className="flex items-center gap-4 text-sm text-gray-500">
                            <span className="flex items-center gap-1">
                              <Github className="h-4 w-4" />
                              {pr.repository}
                            </span>
                            <span>#{pr.number}</span>
                            <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                              pr.state === 'open' ? 'bg-green-100 text-green-800' :
                              pr.state === 'closed' ? 'bg-red-100 text-red-800' :
                              'bg-purple-100 text-purple-800'
                            }`}>
                              {pr.state}
                            </span>
                            <span>{formatTime(pr.createdAt)}</span>
                          </div>
                        </div>
                        <a
                          href={pr.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-gray-400 hover:text-gray-600 transition-colors"
                        >
                          <Github className="h-5 w-5" />
                        </a>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {activity.commits.length === 0 && activity.pullRequests.length === 0 && (
              <div className="bg-white rounded-lg shadow-sm border p-12 text-center">
                <Activity className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 mb-2">No activity found</h3>
                <p className="text-gray-500">No commits or pull requests were found for {formatDate(activity.date)}</p>
              </div>
            )}
          </div>
        ) : null}
      </main>
    </div>
  );
};

export default App;