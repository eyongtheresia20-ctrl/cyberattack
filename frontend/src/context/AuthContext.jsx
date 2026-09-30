import React, { createContext, useContext, useState, useEffect } from 'react';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('phishguard_token') || null);
  const [loading, setLoading] = useState(true);

  const API_URL = '/api/v1';

  useEffect(() => {
    if (token) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000);

      fetch(`${API_URL}/auth/me`, {
        signal: controller.signal,
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })
        .then((res) => {
          if (res.ok) return res.json();
          throw new Error('Token expiré');
        })
        .then((data) => {
          setUser(data.user || data);
        })
        .catch(() => {
          logout();
        })
        .finally(() => {
          clearTimeout(timeoutId);
          setLoading(false);
        });

      return () => {
        clearTimeout(timeoutId);
        controller.abort();
      };
    } else {
      setLoading(false);
    }
  }, [token]);

  const logout = () => {
    localStorage.removeItem('phishguard_token');
    setToken(null);
    setUser(null);
  };

  const parseResponseSafe = async (res) => {
    try {
      const contentType = res.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        return await res.json();
      }
      const text = await res.text();
      return text ? { detail: text } : null;
    } catch {
      return null;
    }
  };

  const login = async (email, password) => {
    let res;
    try {
      res = await fetch(`${API_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
    } catch {
      const netErr = new Error('NETWORK_ERROR');
      netErr.status = 0;
      netErr.detail = 'Cannot connect to backend server';
      throw netErr;
    }
    
    const data = await parseResponseSafe(res);
    if (!res.ok) {
      let detailMsg = (data && typeof data.detail === 'string' && data.detail) ? data.detail : null;
      if (!detailMsg) {
        if (res.status === 401) detailMsg = 'Email ou mot de passe incorrect';
        else if (res.status === 403) detailMsg = 'Compte désactivé';
        else if (res.status >= 500) detailMsg = 'SERVER_ERROR';
        else detailMsg = `HTTP_${res.status}`;
      }
      const err = new Error(detailMsg);
      err.status = res.status;
      err.detail = detailMsg;
      throw err;
    }
    
    localStorage.setItem('phishguard_token', data.token);
    setToken(data.token);
    setUser(data.user);
    return data.user;
  };

  const register = async (nom, prenom, email, password) => {
    let res;
    try {
      res = await fetch(`${API_URL}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ nom, prenom, email, password })
      });
    } catch {
      const netErr = new Error('NETWORK_ERROR');
      netErr.status = 0;
      netErr.detail = 'Cannot connect to backend server';
      throw netErr;
    }
    
    const data = await parseResponseSafe(res);
    if (!res.ok) {
      const detailMsg = (data && typeof data.detail === 'string' && data.detail) ? data.detail : `HTTP_${res.status}`;
      const err = new Error(detailMsg);
      err.status = res.status;
      err.detail = detailMsg;
      throw err;
    }
    
    localStorage.setItem('phishguard_token', data.token);
    setToken(data.token);
    setUser(data.user);
    return data.user;
  };

  const updateUser = (updatedData) => {
    setUser(prev => {
      const newUser = prev ? { ...prev, ...updatedData } : updatedData;
      return newUser;
    });
  };

  const updateProfile = async ({ prenom, nom, email, password, currentPassword, newPassword }) => {
    const headers = { 'Content-Type': 'application/json' };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    let res;
    try {
      res = await fetch(`${API_URL}/auth/profile`, {
        method: 'PUT',
        headers,
        body: JSON.stringify({
          prenom,
          nom,
          email,
          password: password || newPassword || null,
          current_password: currentPassword || null,
          new_password: newPassword || null
        })
      });
    } catch {
      const netErr = new Error('NETWORK_ERROR');
      netErr.status = 0;
      throw netErr;
    }

    const data = await parseResponseSafe(res);
    if (!res.ok) {
      const detailMsg = (data && typeof data.detail === 'string' && data.detail) ? data.detail : `HTTP_${res.status}`;
      const err = new Error(detailMsg);
      err.status = res.status;
      err.detail = detailMsg;
      throw err;
    }

    if (data && data.user) {
      setUser(data.user);
    }
    return data;
  };

  return (
    <AuthContext.Provider value={{ user, token, loading, login, register, logout, updateUser, updateProfile }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const ctx = useContext(AuthContext);
  return ctx || {
    user: null,
    token: null,
    loading: false,
    login: async () => {},
    register: async () => {},
    logout: () => {},
    updateUser: () => {},
    updateProfile: async () => {}
  };
};
