import React, { useState } from 'react';
import { Bot, Send, ShieldCheck, Sparkles, User } from 'lucide-react';
import { api } from '../services/api';

export default function Assistant() {
  const [messages, setMessages] = useState([
    {
      sender: 'assistant',
      text: "Hello! I am your **CyberGuard Defensive Security AI**. Ask me how to remediate detected threats (SQLi, XSS, Brute Force), harden email security (SPF/DKIM/DMARC), or protect your web application architecture.",
      recommendations: [
        "How do I prevent SQL Injection attacks on my backend?",
        "How can I harden my email server against phishing impersonation?",
        "What mitigation steps should I take for XSS vulnerabilities?"
      ]
    }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSend = async (e, textToSend = null) => {
    e?.preventDefault();
    const query = textToSend || input;
    if (!query.trim()) return;

    const newMsgList = [...messages, { sender: 'user', text: query }];
    setMessages(newMsgList);
    setInput('');
    setLoading(true);

    try {
      const res = await api.chatAssistant(query);
      setMessages([
        ...newMsgList,
        {
          sender: 'assistant',
          text: res.data.reply,
          recommendations: res.data.recommendations
        }
      ]);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      <div>
        <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
          <Bot className="w-5 h-5 text-cyan-400" /> AI Cybersecurity Defensive Assistant
        </h2>
        <p className="text-xs text-slate-400">Contextual advice and technical remediation guidance tailored to security findings</p>
      </div>

      {/* Chat Window */}
      <div className="glass-card rounded-xl border border-slate-800 flex flex-col h-[580px]">
        {/* Messages Body */}
        <div className="flex-1 p-5 overflow-y-auto space-y-4">
          {messages.map((m, idx) => (
            <div key={idx} className={`flex gap-3 ${m.sender === 'user' ? 'justify-end' : 'justify-start'}`}>
              {m.sender === 'assistant' && (
                <div className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400 flex-shrink-0">
                  <Sparkles className="w-4 h-4" />
                </div>
              )}

              <div className={`max-w-xl rounded-xl p-4 text-xs space-y-2 ${
                m.sender === 'user'
                  ? 'bg-cyan-600 text-black font-medium'
                  : 'bg-slate-900/90 border border-slate-800 text-slate-200'
              }`}>
                <p className="whitespace-pre-line leading-relaxed font-sans">{m.text}</p>

                {m.recommendations?.length > 0 && (
                  <div className="pt-2 border-t border-slate-800 space-y-1.5">
                    <p className="text-[11px] font-semibold text-cyan-400 uppercase tracking-wider">Suggested Defensive Steps / Inquiries:</p>
                    <div className="flex flex-col gap-1.5">
                      {m.recommendations.map((rec, rIdx) => (
                        <button
                          key={rIdx}
                          onClick={() => handleSend(null, rec)}
                          className="text-left text-[11px] p-2 rounded bg-slate-950/80 hover:bg-slate-800 text-slate-300 hover:text-cyan-300 border border-slate-800/80 transition"
                        >
                          → {rec}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {m.sender === 'user' && (
                <div className="w-8 h-8 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300 flex-shrink-0">
                  <User className="w-4 h-4" />
                </div>
              )}
            </div>
          ))}
          {loading && (
            <div className="flex gap-2 items-center text-xs text-slate-500 font-mono">
              <Sparkles className="w-3.5 h-3.5 text-cyan-400 animate-spin" />
              <span>CyberGuard Security AI is formulating defensive response...</span>
            </div>
          )}
        </div>

        {/* Input Bar */}
        <form onSubmit={handleSend} className="p-3 border-t border-slate-800 flex gap-2 bg-slate-950/50">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask a security question (e.g. 'How do I protect against SQL Injection?')..."
            className="flex-1 bg-slate-900 border border-slate-800 focus:border-cyan-500 rounded-lg px-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none transition"
          />
          <button
            type="submit"
            disabled={loading}
            className="px-5 py-2.5 bg-cyan-500 hover:bg-cyan-400 text-black font-bold text-xs rounded-lg transition shadow-lg shadow-cyan-500/20 flex items-center gap-2"
          >
            <Send className="w-3.5 h-3.5" />
            <span>Send</span>
          </button>
        </form>
      </div>
    </div>
  );
}
