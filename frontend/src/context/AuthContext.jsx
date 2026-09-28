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

  const login = async (email, password) => {
    const res = await fetch(`${API_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.detail || 'Échec de connexion');
    }
    
    localStorage.setItem('phishguard_token', data.token);
    setToken(data.token);
    setUser(data.user);
    return data.user;
  };

  const register = async (nom, prenom, email, password) => {
    const res = await fetch(`${API_URL}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ nom, prenom, email, password })
    });
    
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.detail || "Échec de l'inscription");
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
    const res = await fetch(`${API_URL}/auth/profile`, {
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

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.detail || "Échec de la mise à jour du profil");
    }

    if (data.user) {
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
