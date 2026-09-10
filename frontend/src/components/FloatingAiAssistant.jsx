import React, { useState } from 'react';
import { Bot, X, RefreshCw, Send } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useLanguage } from '../context/LanguageContext';

export default function FloatingAiAssistant() {
  const { user } = useAuth();
  const { lang } = useLanguage();

  const [isChatOpen, setIsChatOpen] = useState(false);
  const [chatMessages, setChatMessages] = useState([
    {
      sender: 'assistant',
      text: lang === 'fr'
        ? `Bonjour ${user?.prenom || 'Alice'} ! Je suis votre assistant de sécurité CyberGuard AI. Posez-moi une question sur une menace cybernétique, un lien ou une règle de sécurité.`
        : `Hello ${user?.prenom || 'Alice'}! I am your CyberGuard AI security assistant. Ask me anything about cyber threats, malicious links, or security best practices.`
    }
  ]);
  const [chatInput, setChatInput] = useState('');
  const [isChatting, setIsChatting] = useState(false);

  const handleSendMessage = async (e) => {
    e.preventDefault();
    if (!chatInput.trim()) return;

    const userText = chatInput;
    setChatInput('');
    setChatMessages(prev => [...prev, { sender: 'user', text: userText }]);
    setIsChatting(true);

    try {
      const res = await fetch('/api/v1/assistant/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: userText, prompt: userText, lang })
      });
      const data = await res.json();
      
      let botReply = data.reply || data.response || (lang === 'fr' ? "Conseil de sécurité appliqué." : "Security advice applied.");
      if (data.recommendations && data.recommendations.length > 0) {
        botReply += "\n\n**" + (lang === 'fr' ? "Recommandations de sécurité :" : "Security Recommendations:") + "**\n" + data.recommendations.map(r => `• ${r}`).join('\n');
      }

      setChatMessages(prev => [...prev, { sender: 'assistant', text: botReply }]);
    } catch (err) {
      setChatMessages(prev => [...prev, {
        sender: 'assistant',
        text: lang === 'fr' ? "L'assistant IA est temporairement indisponible." : "AI Assistant is temporarily unavailable."
      }]);
    } finally {
      setIsChatting(false);
    }
  };

  return (
    <div className="fixed bottom-6 right-6 z-50">
      {!isChatOpen ? (
        <button
          onClick={() => setIsChatOpen(true)}
          className="flex items-center gap-2.5 px-4 py-3 bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-600 hover:to-blue-700 text-white font-extrabold text-xs rounded-full shadow-2xl shadow-sky-500/40 hover:scale-105 transition duration-200 cursor-pointer border border-sky-400/30"
        >
          <div className="relative">
            <Bot className="w-5 h-5" />
            <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-emerald-400 rounded-full animate-ping" />
            <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-emerald-400 rounded-full" />
          </div>
          <span>CyberGuard AI</span>
        </button>
      ) : (
        <div className="bg-white dark:bg-[#111622] border border-sky-100 dark:border-sky-800/60 rounded-3xl shadow-2xl w-80 sm:w-96 flex flex-col h-[480px] overflow-hidden animate-in zoom-in-95 duration-200">
          <div className="p-4 bg-gradient-to-r from-sky-500 to-blue-600 text-white flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="p-2 bg-white/20 rounded-xl backdrop-blur-sm">
                <Bot className="w-5 h-5" />
              </div>
              <div>
                <h4 className="font-extrabold text-sm">CyberGuard AI</h4>
                <p className="text-[10px] text-sky-100 font-medium">
                  {lang === 'fr' ? 'En ligne • Assistant Cybersécurité' : 'Online • Cybersecurity Advisor'}
                </p>
              </div>
            </div>
            <button onClick={() => setIsChatOpen(false)} className="p-1 text-white/80 hover:text-white rounded-lg cursor-pointer">
              <X className="w-5 h-5" />
            </button>
          </div>

          <div className="flex-1 p-4 overflow-y-auto space-y-3 bg-slate-50/50 dark:bg-[#090d16]/50 text-xs">
            {chatMessages.map((msg, idx) => (
              <div key={idx} className={`flex ${msg.sender === 'user' ? 'justify-end' : 'justify-start'}`}>
                <div className={`max-w-[85%] rounded-2xl p-3 leading-relaxed ${
                  msg.sender === 'user'
                    ? 'bg-sky-500 text-white rounded-br-none shadow-md'
                    : 'bg-white dark:bg-[#1a2333] text-slate-800 dark:text-slate-200 border border-sky-100 dark:border-sky-800/40 rounded-bl-none shadow-sm'
                }`}>
                  {msg.text}
                </div>
              </div>
            ))}
            {isChatting && (
              <div className="flex justify-start">
                <div className="bg-white dark:bg-[#1a2333] text-slate-400 p-2.5 rounded-2xl text-[11px] flex items-center gap-2 border border-sky-100 dark:border-sky-800/40">
                  <RefreshCw className="w-3.5 h-3.5 animate-spin text-sky-500" />
                  {lang === 'fr' ? 'CyberGuard AI réfléchit...' : 'CyberGuard AI is thinking...'}
                </div>
              </div>
            )}
          </div>

          <form onSubmit={handleSendMessage} className="p-3 bg-white dark:bg-[#111622] border-t border-sky-100 dark:border-sky-800/40 flex gap-2">
            <input
              type="text"
              placeholder={lang === 'fr' ? 'Posez une question à CyberGuard AI...' : 'Ask CyberGuard AI a question...'}
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              className="flex-1 px-4 py-2.5 bg-slate-50 dark:bg-[#1a2333] border border-sky-100 dark:border-sky-800/60 rounded-xl text-xs text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:border-sky-500 font-sans"
            />
            <button
              type="submit"
              disabled={isChatting}
              className="p-2.5 bg-sky-500 hover:bg-sky-600 text-white rounded-xl shadow-md transition cursor-pointer disabled:opacity-50"
            >
              <Send className="w-4 h-4" />
            </button>
          </form>
        </div>
      )}
    </div>
  );
}
