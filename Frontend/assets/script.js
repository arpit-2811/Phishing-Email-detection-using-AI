
(function () {

  // Centralized Firebase Config
  const firebaseConfig = {
    apiKey: "AIzaSyAVr8nmPu0VtKAEVgfR7yxMSaOmMOjyAWk",
    authDomain: "phishgaurd-6231d.firebaseapp.com",
    projectId: "phishgaurd-6231d",
    storageBucket: "phishgaurd-6231d.appspot.com",
    messagingSenderId: "629465563275",
    appId: "1:629465563275:web:edbe344ca4f74d509ed48e"
  };

  // Initialize Firebase if loaded and not already initialized
  if (typeof firebase !== 'undefined' && !firebase.apps.length) {
    firebase.initializeApp(firebaseConfig);
  }

  let db;
  if (typeof firebase !== 'undefined') {
    db = firebase.firestore();
  }

  // mark nav active based on path
  function markNav() {
    const links = document.querySelectorAll('.navlink');
    links.forEach(a => {
      // Reset classes
      a.classList.remove('text-indigo-600', 'bg-indigo-50', 'dark:bg-indigo-900/30', 'dark:text-indigo-400', 'font-semibold');
      a.classList.add('text-slate-600', 'dark:text-slate-300');

      const href = a.getAttribute('href');
      const page = a.getAttribute('data-page');

      const currentPath = location.pathname.split('/').pop();
      const isHome = currentPath === '' || currentPath === 'index.html';

      let isActive = false;
      if (href === currentPath) isActive = true;
      if (isHome && href === 'index.html') isActive = true;

      // Fix for home page being index.html but href being just "index.html"
      if (href === 'index.html' && (currentPath === '' || currentPath === '/')) isActive = true;

      if (isActive) {
        a.classList.remove('text-slate-600', 'dark:text-slate-300');
        a.classList.add('text-indigo-600', 'dark:text-indigo-400', 'bg-indigo-50', 'dark:bg-indigo-900/30', 'font-semibold');
      }
    });
  }

  // Mobile Menu Logic
  function initMobileMenu() {
    const btn = document.getElementById('mobileMenuBtn');
    const menu = document.getElementById('mobileMenu');

    if (btn && menu) {
      btn.addEventListener('click', () => {
        menu.classList.toggle('hidden');
        // Optional: Animate icon
      });
    }
  }

  // Navbar Scroll Effect
  function initNavbarScroll() {
    const nav = document.getElementById('navbar');
    if (!nav) return;

    window.addEventListener('scroll', () => {
      if (window.scrollY > 10) {
        nav.classList.add('shadow-md');
        nav.classList.replace('bg-transparent', 'glass-nav'); // If we started transparent
      } else {
        nav.classList.remove('shadow-md');
      }
    });
  }

  // Home Page Logic
  function initHome() {
    const homeBtn = document.getElementById('homeAnalyzeBtn');
    const homeInput = document.getElementById('homeInput');

    if (homeBtn && homeInput) {
      homeBtn.addEventListener('click', () => {
        const text = homeInput.value.trim();
        if (!text) {
          alert('Please paste some email text first.');
          return;
        }
        // Store in localStorage to pass to Analyze page
        localStorage.setItem('pg_analyze_text', text);
        window.location.href = 'analyze.html';
      });
    }
  }

  // Real AI Analysis via Python Backend
  async function analyzeContent(text) {
    if (!text) return null;

    try {
      const response = await fetch('https://phishing-email-detection-using-ai.onrender.com/api/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ text: text })
      });

      if (!response.ok) throw new Error('Server detected error');

      const data = await response.json();
      return {
        date: new Date().toISOString(),
        subject: (text.split('\n')[0] || '(No Subject)').substring(0, 60),
        score: data.score,
        type: data.type,
        summary: data.summary,
        findings: data.findings || [],
        links: (text.match(/https?:\/\/[^\s]+/g) || []).length
      };
    } catch (e) {
      console.error("Backend Error, falling back to offline mode:", e);
      // Fallback Mock Logic (Offline Mode)
      return analyzeContentOffline(text);
    }
  }

  // Offline Fallback (Previous Mock Logic)
  function analyzeContentOffline(text) {
    const txt = text.toLowerCase();

    // 1. Detect Spam Type
    let type = "suspicious"; // default
    let reason = "Contextual analysis suggests potential risk.";
    const types = {
      "Urgent Action": ["urgent", "immediate", "suspend", "24 hours", "terminate", "lock"],
      "Financial Fraud": ["bank", "verify", "account", "transaction", "payment", "invoice", "paypal"],
      "Credentials Harvesting": ["login", "password", "click here", "sign in", "update"],
      "Prize/Lottery": ["won", "prize", "lottery", "claim", "winner", "reward"],
      "Extortion": ["recorded", "cam", "video", "bitcoin", "pay"]
    };

    let riskScore = 15; // Base score
    let detectedTypes = [];

    for (const [t, keywords] of Object.entries(types)) {
      const matches = keywords.filter(k => txt.includes(k));
      if (matches.length > 0) {
        detectedTypes.push(t);
        riskScore += matches.length * 10;
      }
    }

    // Link analysis
    const linkCount = (txt.match(/https?:\/\/[^\s]+/g) || []).length;
    if (linkCount > 0) {
      riskScore += linkCount * 15;
      detectedTypes.push("Suspicious Links");
    }

    // Cap score
    riskScore = Math.min(99, Math.max(10, riskScore));

    // Refine Type & Reason
    if (detectedTypes.length > 0) {
      type = detectedTypes[0]; // Primary type
      reason = `Detected patterns related to ${detectedTypes.join(", ")}. The email uses specific keywords known to be associated with phishing attacks.`;
    }

    if (riskScore < 30) {
      type = "Safe";
      reason = "No significant threats detected. Standard caution advised.";
    }

    return {
      date: new Date().toISOString(),
      subject: (text.split('\n')[0] || '(No Subject)').substring(0, 60),
      score: riskScore,
      type: type,
      summary: reason + " (Offline Mode)",
      findings: detectedTypes,
      links: linkCount
    };
  }

  // Analyze page bindings
  function initAnalyze() {
    const emailText = document.getElementById('emailText');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const clearBtn = document.getElementById('clearBtn');
    const resultPanel = document.getElementById('resultPanel');
    const recentList = document.getElementById('recentList');

    // UI Elements for Result
    const resultScore = document.getElementById('resultScore');
    const resultHeadline = document.getElementById('resultHeadline');
    const rb1 = document.getElementById('rb1'); // Type
    const rb2 = document.getElementById('rb2'); // Risk Level
    const rb3 = document.getElementById('rb3'); // Links
    const rb4 = document.getElementById('rb4'); // Findings

    // Check for passed text
    const passedText = localStorage.getItem('pg_analyze_text');
    if (passedText && emailText) {
      emailText.value = passedText;
      localStorage.removeItem('pg_analyze_text');
      setTimeout(() => { if (analyzeBtn) analyzeBtn.click(); }, 300);
    }

    // Toggle Panels
    const tabs = ['tabPaste', 'tabUpload', 'tabUrl'];
    const panels = ['panelPaste', 'panelUpload', 'panelUrl'];

    tabs.forEach((t, i) => {
      const btn = document.getElementById(t);
      if (btn) {
        btn.addEventListener('click', () => {
          tabs.forEach(tab => document.getElementById(tab)?.classList.remove('bg-indigo-50', 'text-indigo-700', 'border-indigo-200'));
          panels.forEach(p => document.getElementById(p)?.classList.add('hidden'));

          btn.classList.add('bg-indigo-50', 'text-indigo-700', 'border-indigo-200');
          document.getElementById(panels[i])?.classList.remove('hidden');
        });
      }
    });

    if (analyzeBtn) {
      analyzeBtn.addEventListener('click', async () => {
        let txt = '';
        const fileInput = document.getElementById('fileIn');
        const urlInput = document.getElementById('urlInput');

        // Determine Source
        if (!document.getElementById('panelPaste').classList.contains('hidden')) {
          txt = emailText.value || '';
        } else if (!document.getElementById('panelUpload').classList.contains('hidden')) {
          if (fileInput && fileInput.files.length > 0) {
            try {
              txt = await fileInput.files[0].text();
            } catch (e) {
              alert("Error reading file");
              return;
            }
          } else {
            alert("Please select a file to upload.");
            return;
          }
        } else if (!document.getElementById('panelUrl').classList.contains('hidden')) {
          txt = urlInput.value || '';
        }

        if (!txt.trim()) { alert('Please provide content to analyze'); return; }

        // Loading State
        const originalText = analyzeBtn.innerHTML;
        analyzeBtn.innerHTML = '<span class="animate-spin">↻</span> Analyzing...';
        analyzeBtn.disabled = true;

        setTimeout(async () => {
          // Perform Analysis
          const report = await analyzeContent(txt);

          // Update UI
          if (resultScore) resultScore.innerText = report.score + '%';
          if (resultHeadline) {
            resultHeadline.innerText = report.score > 70 ? 'High Risk Detected' : (report.score > 40 ? 'Suspicious Content' : 'Likely Safe');
            resultHeadline.className = `text-2xl font-bold mt-1 ${report.score > 70 ? 'text-red-600' : (report.score > 40 ? 'text-amber-500' : 'text-green-600')}`;
          }

          if (rb1) rb1.innerText = report.type;
          if (rb2) {
            rb2.innerText = report.score > 70 ? 'Critical' : (report.score > 40 ? 'Moderate' : 'Low');
            rb2.className = `text-sm font-bold ${report.score > 70 ? 'text-red-500' : (report.score > 40 ? 'text-amber-500' : 'text-green-500')}`;
          }
          if (rb3) {
            rb3.innerText = report.links > 0 ? `${report.links} Found` : 'None';
            rb3.className = `text-sm font-bold ${report.links > 0 ? 'text-amber-500' : 'text-green-500'}`;
          }
          if (rb4) {
            rb4.innerText = report.findings.length > 0 ? report.findings.slice(0, 2).join(', ') : 'Clean';
            rb4.className = "text-sm font-bold text-slate-500 truncate max-w-[100px]";
          }

          // Show Result
          if (resultPanel) {
            resultPanel.classList.remove('hidden');
            resultPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
          }

          // Save Report to Firestore (Only if Logged In)
          if (typeof firebase !== 'undefined' && firebase.auth().currentUser) {
            const uid = firebase.auth().currentUser.uid;

            // Save to Firestore
            db.collection('users').doc(uid).collection('reports').add(report)
              .then(() => {
                console.log("Report saved to Firestore");
                // Optional: Notify user implicitly or via small toast
              })
              .catch((error) => {
                console.error("Error adding document: ", error);
                alert("Error saving report to database: " + error.message);
              });
          } else {
            console.log("User not logged in, report not saved to Firestore.");
            alert("⚠️ You are NOT logged in!\n\nThis report will NOT be saved to the database. Please Login first.");
          }

          // --- AI Chat Setup ---
          window.lastReport = report;
          const aiChat = document.getElementById('aiChat');
          if (aiChat) {
            aiChat.innerHTML = '<div class="text-slate-500 dark:text-slate-400 text-xs text-center my-2">- Analysis Context Loaded -</div><div class="bg-indigo-50 dark:bg-indigo-900/20 p-2 rounded-lg rounded-tl-none self-start text-slate-700 dark:text-slate-300 text-sm max-w-[85%] mb-2">I have analyzed this content. I found it to be <b>' + report.score + '% Risk</b>. Ask me "Why?" or "Is it safe?".</div>';
          }

          // Reset Button
          analyzeBtn.innerHTML = originalText;
          analyzeBtn.disabled = false;
        }, 1500); // Realistic delay
      });
    }

    // AI Chat Interaction
    const askBtn = document.getElementById('askBtn');
    const aiQuestion = document.getElementById('aiQuestion');
    const aiChat = document.getElementById('aiChat');

    if (askBtn && aiQuestion && aiChat) {
      askBtn.addEventListener('click', async () => {
        const q = aiQuestion.value.trim();
        if (!q) return;

        if (!window.lastReport) {
          aiChat.innerHTML += `<div class="bg-red-50 text-red-600 p-2 rounded-lg text-sm mb-2">Please run an analysis first!</div>`;
          return;
        }

        // User Msg
        aiChat.innerHTML += `<div class="flex justify-end mb-2"><div class="bg-slate-900 dark:bg-white text-white dark:text-slate-900 p-2 rounded-lg rounded-tr-none text-sm max-w-[85%]">${q.replace(/</g, '&lt;')}</div></div>`;
        aiQuestion.value = '';
        aiChat.scrollTop = aiChat.scrollHeight;

        // Simulate Thinking
        const thinkingId = 'thinking-' + Date.now();
        aiChat.innerHTML += `<div id="${thinkingId}" class="flex justify-start mb-2"><div class="bg-indigo-50 dark:bg-slate-800 text-slate-500 text-xs p-2 rounded-lg italic">Thinking...</div></div>`;
        aiChat.scrollTop = aiChat.scrollHeight;

        try {
          const res = await fetch('https://phishing-email-detection-using-ai.onrender.com/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ question: q, context: window.lastReport })
          });
          const data = await res.json();

          // Remove thinking
          const thinkEl = document.getElementById(thinkingId);
          if (thinkEl) thinkEl.remove();

          // Bot Msg
          aiChat.innerHTML += `<div class="flex justify-start mb-2"><div class="bg-indigo-50 dark:bg-indigo-900/20 text-slate-700 dark:text-slate-300 p-2 rounded-lg rounded-tl-none text-sm max-w-[85%] border border-indigo-100 dark:border-indigo-900/30 shadow-sm">${data.answer}</div></div>`;
          aiChat.scrollTop = aiChat.scrollHeight;

        } catch (e) {
          console.error(e);
          const thinkEl = document.getElementById(thinkingId);
          if (thinkEl) thinkEl.remove();
          aiChat.innerHTML += `<div class="text-red-500 text-xs">Error connecting to AI.</div>`;
        }
      });

      // Allow Enter key
      aiQuestion.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') askBtn.click();
      });
    }

    // AI Chat Expand/Collapse
    const expandBtn = document.getElementById('expandChatBtn');
    if (expandBtn && aiChat) {
      expandBtn.addEventListener('click', () => {
        aiChat.classList.toggle('h-40');
        aiChat.classList.toggle('h-96');
        aiChat.classList.toggle('transition-all');
        aiChat.classList.toggle('duration-300');
      });
    }

    if (clearBtn) clearBtn.addEventListener('click', () => {
      if (emailText) emailText.value = '';
      if (resultPanel) resultPanel.classList.add('hidden');
    });

    function renderRecent(uidParam) {
      // Try to get UID if not passed
      const uid = uidParam || (firebase.auth().currentUser ? firebase.auth().currentUser.uid : null);
      if (!uid) {
        if (recentList) recentList.innerHTML = '<li class="text-sm text-slate-500 text-center italic py-2">Login to save your scan history.</li>';
        return;
      }

      const history = JSON.parse(localStorage.getItem(`pg_reports_${uid}`) || '[]');
      if (!recentList) return;
      recentList.innerHTML = '';

      if (history.length === 0) {
        recentList.innerHTML = '<li class="text-sm text-slate-500 text-center italic">No recent scans found.</li>';
        return;
      }

      history.slice(0, 5).forEach(r => {
        const li = document.createElement('li');
        li.className = "py-3 border-b border-gray-100 dark:border-slate-800 last:border-0 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors rounded px-2 cursor-pointer";
        li.innerHTML = `
          <div class="flex justify-between items-center mb-1">
             <span class="font-medium text-slate-800 dark:text-slate-200 text-sm truncate w-2/3">${r.subject}</span>
             <span class="text-xs font-bold px-2 py-0.5 rounded ${r.score > 70 ? 'bg-red-100 text-red-600' : 'bg-green-100 text-green-600'}">${r.score}% Risk</span>
          </div>
          <div class="text-xs text-slate-500 dark:text-slate-400 flex justify-between">
             <span>${r.type}</span>
             <span>${new Date(r.date).toLocaleDateString()}</span>
          </div>
        `;
        recentList.appendChild(li);
      });
    }
    renderRecent();

  }




  // Reports Page Logic
  function initReports() {
    const tableBody = document.getElementById('reportsTable');
    const container = document.getElementById('reportsContainer');
    const prompt = document.getElementById('loginPrompt');

    // Check Auth using Firebase
    if (typeof firebase === 'undefined' || !firebase.auth) return;

    firebase.auth().onAuthStateChanged(user => {
      if (!tableBody || !container || !prompt) return;

      if (user) {
        // Show Reports, Hide Prompt
        container.classList.remove('hidden');
        prompt.classList.add('hidden');

        // Load User-Specific Reports Real-time
        db.collection('users').doc(user.uid).collection('reports')
          .orderBy('date', 'desc')
          .onSnapshot((querySnapshot) => {
            const history = [];
            querySnapshot.forEach((doc) => {
              history.push({ id: doc.id, ...doc.data() });
            });
            renderTable(history);
          });
      } else {
        // Hide Reports, Show Prompt
        container.classList.add('hidden');
        prompt.classList.remove('hidden');
      }
    });

    function renderTable(history) {
      tableBody.innerHTML = '';
      if (history.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="4" class="py-12 text-center text-slate-500 italic">No reports found. Analyze an email to get started.</td></tr>';
        return;
      }

      history.forEach((r, idx) => {
        const row = document.createElement('tr');
        // Make row clickable
        row.className = "border-b border-gray-100 dark:border-slate-800 hover:bg-indigo-50 dark:hover:bg-slate-800/50 transition-colors cursor-pointer group";
        row.onclick = () => window.openReportModal(r);

        row.innerHTML = `
                <td class="px-6 py-4 whitespace-nowrap text-sm text-slate-500 dark:text-slate-400">
                ${new Date(r.date).toLocaleDateString()} <span class="hidden sm:inline text-xs opacity-75 ml-1">${new Date(r.date).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                </td>
                <td class="px-6 py-4 text-sm font-medium text-slate-900 dark:text-white max-w-xs truncate relative">
                ${r.subject}
                <div class="text-xs font-normal text-slate-500 mt-0.5 truncate">${r.summary}</div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                <span class="px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full bg-slate-100 text-slate-800 dark:bg-slate-800 dark:text-slate-300">
                    ${r.type}
                </span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-right">
                <span class="text-sm font-bold ${r.score > 70 ? 'text-red-600' : (r.score > 40 ? 'text-amber-500' : 'text-green-600')}">
                    ${r.score}%
                </span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-right">
                <td class="px-6 py-4 whitespace-nowrap text-right">
                    <button onclick="event.stopPropagation(); window.shareReport(${JSON.stringify(r).replace(/"/g, '&quot;')})" 
                        class="p-2 text-slate-400 hover:text-indigo-600 transition-colors" title="Share Copy">
                        <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z" /></svg>
                    </button>
                    <button onclick="event.stopPropagation(); window.deleteReport('${r.id}')" 
                        class="p-2 text-slate-400 hover:text-red-600 transition-colors" title="Delete">
                        <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
                    </button>
                </td>
            `;
        tableBody.appendChild(row);
      });
    }
  }

  // Modal Logic (Global for access)
  // ---------------------------------------------------------
  // Modal Logic (Global)
  // ---------------------------------------------------------
  window.openReportModal = function (r) {
    const m = document.getElementById('reportModal');
    if (!m) return;

    // 1. Header Info
    const dateEl = document.getElementById('modalDate');
    if (dateEl) dateEl.textContent = new Date(r.date || Date.now()).toLocaleString();

    const subjEl = document.getElementById('modalSubject');
    if (subjEl) subjEl.textContent = r.subject || 'No Subject';

    // 2. Score & Risk
    const scoreBox = document.getElementById('modalScoreBox');
    if (scoreBox) {
      scoreBox.textContent = r.score + '%';
      // Set border color based on score
      const colorClass = r.score > 70 ? 'border-red-500 text-red-600' : (r.score > 40 ? 'border-amber-500 text-amber-600' : 'border-green-500 text-green-600');
      // Reset classes first if needed, or just set style. 
      // Using styling for border color to be safe + class for text
      scoreBox.className = `w-16 h-16 rounded-full flex items-center justify-center text-xl font-bold border-4 ${colorClass}`;
    }

    const riskLabel = document.getElementById('modalRiskLabel');
    if (riskLabel) {
      riskLabel.textContent = r.score > 70 ? 'High Risk' : (r.score > 40 ? 'Medium Risk' : 'Low Risk');
      riskLabel.className = `text-lg font-bold ${r.score > 70 ? 'text-red-600' : (r.score > 40 ? 'text-amber-500' : 'text-green-600')}`;
    }

    // 3. Details
    const summaryEl = document.getElementById('modalSummary');
    if (summaryEl) summaryEl.textContent = r.summary || 'No summary available.';

    const typeEl = document.getElementById('modalType');
    if (typeEl) typeEl.textContent = r.type || 'Unknown';

    const linksEl = document.getElementById('modalLinks');
    if (linksEl) linksEl.textContent = (r.links !== undefined ? r.links : '?') + ' Found';

    // 4. Findings
    const findingsList = document.getElementById('modalFindings');
    if (findingsList) {
      findingsList.innerHTML = '';
      if (r.findings && r.findings.length) {
        r.findings.forEach(f => {
          const li = document.createElement('li');
          // li.className = 'flex items-start gap-2'; // Existing logic
          li.innerHTML = `<span class="text-red-500 font-bold mr-2">•</span>${f}`;
          findingsList.appendChild(li);
        });
      } else {
        findingsList.innerHTML = '<li class="text-slate-400 italic">No specific threat indicators found.</li>';
      }
    }

    // Attach Button Actions
    const delBtn = document.getElementById('modalDeleteBtn');
    if (delBtn) delBtn.onclick = () => window.deleteReport(r.id);

    const dlBtn = document.getElementById('modalDownloadBtn');
    if (dlBtn) dlBtn.onclick = () => window.downloadReport(r);

    const shareBtn = document.getElementById('modalShareBtn');
    if (shareBtn) shareBtn.onclick = () => window.shareReport(r);

    const feedBtn = document.getElementById('modalShareFeedBtn');
    if (feedBtn) feedBtn.onclick = () => window.shareToFeed(r);

    m.classList.remove('hidden');
  }

  window.closeReportModal = function () {
    document.getElementById('reportModal').classList.add('hidden');
  };

  // ---------------------------------------------------------
  // Awareness Feed Logic
  // ---------------------------------------------------------

  // 1. Create Post Modal
  window.selectedTopics = new Set();

  window.toggleTopic = function (btn) {
    const topic = btn.getAttribute('data-topic');
    if (window.selectedTopics.has(topic)) {
      window.selectedTopics.delete(topic);
      btn.classList.remove('bg-indigo-100', 'text-indigo-700', 'border-indigo-200', 'dark:bg-indigo-900/40', 'dark:text-indigo-300');
      btn.classList.add('text-slate-600', 'dark:text-slate-400');
    } else {
      window.selectedTopics.add(topic);
      btn.classList.add('bg-indigo-100', 'text-indigo-700', 'border-indigo-200', 'dark:bg-indigo-900/40', 'dark:text-indigo-300');
      btn.classList.remove('text-slate-600', 'dark:text-slate-400');
    }
  };

  window.openCreatePostModal = function (prefillData) {
    if (typeof firebase !== 'undefined' && !firebase.auth().currentUser) {
      alert("Please login to share a report.");
      window.location.href = 'login.html';
      return;
    }

    const modal = document.getElementById('createPostModal');
    if (!modal) return;

    // Reset or Prefill
    document.getElementById('postTitle').value = prefillData?.title || prefillData?.subject || '';
    document.getElementById('postDesc').value = prefillData?.comment || ''; // User's comment on the report

    // Prefill Email Content if available
    const contentBox = document.getElementById('postContent');
    if (contentBox) contentBox.value = prefillData?.emailContent || '';

    // Hidden Storage for Report Data
    window.currentReportData = prefillData?.report || null;

    window.selectedTopics.clear();
    document.querySelectorAll('.topic-btn').forEach(btn => {
      btn.classList.remove('bg-indigo-100', 'text-indigo-700', 'dark:bg-indigo-900/40');
      btn.classList.add('text-slate-600', 'dark:text-slate-400');
    });

    // Updated to render attachment state
    window.renderAttachedReportUI();


    modal.classList.remove('hidden');
  };

  window.feedCache = {}; // Cache for post data to be accessed by modals

  window.openPostDetails = function (pid) {
    const data = window.feedCache[pid];
    if (!data) return;

    const modal = document.getElementById('postDetailsModal');
    if (!modal) return;

    // 1. Header Info
    document.getElementById('modalDate').textContent = data.timestamp ? new Date(data.timestamp.toDate()).toLocaleString() : 'Just now';
    document.getElementById('modalSubject').textContent = data.title || 'No Title';
    document.getElementById('modalAuthor').textContent = `Posted by @${data.authorName || 'Unknown'}`;

    // 2. Email Content
    const emailSection = document.getElementById('modalEmailSection');
    const emailContent = document.getElementById('modalEmailContent');
    if (data.emailContent) {
      emailSection.classList.remove('hidden');
      emailContent.textContent = data.emailContent;
    } else {
      emailSection.classList.add('hidden');
      emailContent.textContent = '';
    }

    // 3. Report Section
    const reportSection = document.getElementById('modalReportSection');
    if (data.reportData) {
      reportSection.classList.remove('hidden');
      const r = data.reportData;

      document.getElementById('modalRiskLabel').textContent = `${r.score}% Risk Score`;

      // Score Box Color
      const scoreBox = document.getElementById('modalScoreBox');
      scoreBox.textContent = r.score;
      if (r.score > 70) {
        scoreBox.className = "w-16 h-16 rounded-full flex items-center justify-center text-xl font-bold border-4 border-red-200 text-red-600 bg-red-50";
        document.getElementById('modalRiskLabel').className = "text-lg font-bold text-red-600";
      } else if (r.score > 40) {
        scoreBox.className = "w-16 h-16 rounded-full flex items-center justify-center text-xl font-bold border-4 border-amber-200 text-amber-600 bg-amber-50";
        document.getElementById('modalRiskLabel').className = "text-lg font-bold text-amber-600";
      } else {
        scoreBox.className = "w-16 h-16 rounded-full flex items-center justify-center text-xl font-bold border-4 border-green-200 text-green-600 bg-green-50";
        document.getElementById('modalRiskLabel').className = "text-lg font-bold text-green-600";
      }

      document.getElementById('modalSummary').textContent = r.summary || 'No summary available.';
      document.getElementById('modalType').textContent = r.type || 'Unknown';
      document.getElementById('modalLinks').textContent = r.links !== undefined ? r.links : 'N/A';

      const findingsUl = document.getElementById('modalFindings');
      findingsUl.innerHTML = '';
      if (r.findings && r.findings.length > 0) {
        r.findings.forEach(f => {
          const li = document.createElement('li');
          li.textContent = f;
          findingsUl.appendChild(li);
        });
      } else {
        findingsUl.innerHTML = '<li class="italic text-slate-400">No specific findings listed.</li>';
      }

    } else {
      reportSection.classList.add('hidden');
    }

    modal.classList.remove('hidden');
  };

  window.closePostDetailsModal = function () {
    document.getElementById('postDetailsModal').classList.add('hidden');
  };

  window.renderAttachedReportUI = function () {
    const wrapperNo = document.getElementById('noReportAttached');
    const wrapperYes = document.getElementById('reportAttachedPreview');
    const badge = document.getElementById('attachedRiskBadge');
    const subj = document.getElementById('attachedSubject');

    if (!wrapperNo || !wrapperYes) return;

    if (window.currentReportData) {
      wrapperNo.classList.add('hidden');
      wrapperYes.classList.remove('hidden');

      const r = window.currentReportData;
      subj.textContent = r.subject || '(No Subject)';
      badge.textContent = r.score + '%';

      // Color
      const colorClass = r.score > 70 ? 'text-red-600' : (r.score > 40 ? 'text-amber-600' : 'text-green-600');
      badge.className = `flex-shrink-0 w-10 h-10 rounded-full bg-white dark:bg-slate-800 flex items-center justify-center font-bold text-xs shadow-sm border ${r.score > 70 ? 'border-red-200' : 'border-slate-100'} ${colorClass}`;
    } else {
      wrapperNo.classList.remove('hidden');
      wrapperYes.classList.add('hidden');
    }
  };

  window.removeAttachedReport = function () {
    window.currentReportData = null;
    window.renderAttachedReportUI();
  };

  window.openSelectReportModal = function () {
    const modal = document.getElementById('selectReportModal');
    const list = document.getElementById('selectReportList');
    if (!modal || !list) return;

    modal.classList.remove('hidden');
    list.innerHTML = '<div class="text-center text-slate-500 text-sm py-4">Loading reports...</div>';

    const user = firebase.auth().currentUser;
    if (!user) {
      list.innerHTML = '<div class="text-center text-red-500 text-sm py-4">Please login to view reports.</div>';
      return;
    }

    db.collection('users').doc(user.uid).collection('reports')
      .orderBy('date', 'desc')
      .limit(20)
      .get()
      .then(snap => {
        if (snap.empty) {
          list.innerHTML = '<div class="text-center text-slate-500 text-sm py-4">No saved reports found.</div>';
          return;
        }

        list.innerHTML = '';
        snap.forEach(doc => {
          const r = doc.data();
          // We store the full object on the button click handler
          // Escape quotes for safety
          const rStr = JSON.stringify(r).replace(/"/g, '&quot;');

          const item = document.createElement('div');
          item.className = "p-3 rounded-lg border border-slate-200 dark:border-slate-800 hover:bg-indigo-50 dark:hover:bg-slate-800 cursor-pointer transition-colors flex justify-between items-center group";
          item.onclick = function () { window.selectReport(r); };

          item.innerHTML = `
                    <div class="truncate pr-2">
                        <div class="font-medium text-slate-800 dark:text-slate-200 text-sm truncate">${r.subject || 'No Subject'}</div>
                        <div class="text-xs text-slate-500">${new Date(r.date).toLocaleDateString()} • ${r.type}</div>
                    </div>
                    <div class="font-bold text-xs px-2 py-1 rounded ${r.score > 70 ? 'bg-red-100 text-red-600' : (r.score > 40 ? 'bg-amber-100 text-amber-600' : 'bg-green-100 text-green-600')}">
                        ${r.score}%
                    </div>
                `;
          list.appendChild(item);
        });
      })
      .catch(err => {
        console.error(err);
        list.innerHTML = '<div class="text-center text-red-500 text-sm py-4">Error loading reports.</div>';
      });
  };

  window.closeSelectReportModal = function () {
    document.getElementById('selectReportModal').classList.add('hidden');
  };

  window.selectReport = function (r) {
    window.currentReportData = r;
    window.renderAttachedReportUI();
    window.closeSelectReportModal();

    // Auto-fill Title if empty
    const titleInput = document.getElementById('postTitle');
    if (titleInput && !titleInput.value) {
      titleInput.value = r.subject;
    }

    // Auto-select topic if possible? (Optional enhancement)
  };

  window.closeCreatePostModal = function () {
    document.getElementById('createPostModal').classList.add('hidden');
    window.currentReportData = null;
  };

  window.submitPost = function () {
    const user = firebase.auth().currentUser;
    if (!user) return;

    const title = document.getElementById('postTitle').value.trim();
    const desc = document.getElementById('postDesc').value.trim();
    const content = document.getElementById('postContent') ? document.getElementById('postContent').value.trim() : '';
    const topics = Array.from(window.selectedTopics);

    if (!title) {
      alert("Please enter a subject line.");
      return;
    }

    const newPost = {
      authorId: user.uid,
      authorName: user.email.split('@')[0], // Simple username
      title: title,
      description: desc,
      emailContent: content, // The raw suspect email
      reportData: window.currentReportData, // Attached Analysis Report (Score, Type)
      topics: topics,
      timestamp: firebase.firestore.FieldValue.serverTimestamp(),
      likes: [], // Array of UIDs
      comments: 0
    };

    const btn = document.querySelector('button[onclick="window.submitPost()"]');
    const originalText = btn.innerText;
    btn.innerText = "Posting...";
    btn.disabled = true;

    db.collection('posts').add(newPost).then(() => {
      window.closeCreatePostModal();
      btn.innerText = originalText;
      btn.disabled = false;
      // Feed listener will auto-update
    }).catch(err => {
      console.error(err);
      alert("Error creating post.");
      btn.innerText = originalText;
      btn.disabled = false;
    });
  };

  // 2. Feed Rendering & Interactions
  window.initFeed = function () {
    const grid = document.getElementById('feedGrid');
    const empty = document.getElementById('feedEmpty');

    // Check for Draft from Analysis Page
    const draft = localStorage.getItem('pg_feed_draft');
    if (draft) {
      // Wait for Auth to settle before opening modal
      if (typeof firebase !== 'undefined') {
        const unsub = firebase.auth().onAuthStateChanged(user => {
          if (user) {
            try {
              const data = JSON.parse(draft);
              if (window.openCreatePostModal) {
                window.openCreatePostModal({
                  title: data.report.subject,
                  emailContent: data.emailContent,
                  report: data.report,
                  comment: ''
                });
              }
            } catch (e) { console.error("Draft parse error", e); }
            localStorage.removeItem('pg_feed_draft'); // Clear only after success
          } else {
            // Not logged in (really), let modal handle it or prompt
            // If we strictly want to allow them to login first, we might leave it.
            // But since the user IS logged in, this listener will fire with 'user' object once ready.
          }
          unsub(); // Run once
        });
      }
    }


    if (!grid) return;

    db.collection('posts').orderBy('timestamp', 'desc').limit(20)
      .onSnapshot(snapshot => {
        if (snapshot.empty) {
          grid.innerHTML = '';
          empty.classList.remove('hidden');
          return;
        }

        empty.classList.add('hidden');
        grid.innerHTML = '';
        const user = firebase.auth().currentUser;
        const uid = user ? user.uid : null;

        snapshot.forEach(doc => {
          const data = doc.data();
          const pid = doc.id;
          const liked = data.likes && data.likes.includes(uid);

          // Cache for Details View
          window.feedCache[pid] = data;

          // Format Topics
          const topicsHtml = (data.topics || []).map(t =>
            `<span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wide bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700">${t}</span>`
          ).join('');

          // Risk Badge (if report attached)
          let riskBadge = '';
          if (data.reportData && data.reportData.score) {
            const s = data.reportData.score;
            const color = s > 70 ? 'bg-red-100 text-red-600 border-red-200' : (s > 40 ? 'bg-amber-100 text-amber-600 border-amber-200' : 'bg-green-100 text-green-600 border-green-200');
            riskBadge = `<span class="px-2.5 py-0.5 rounded-full text-xs font-bold border ${color} ml-2">${s}% Risk</span>`;
          }

          // Email Content Snippet
          let contentSnippet = '';
          if (data.emailContent) {
            contentSnippet = `
                    <div class="mt-3 p-3 bg-slate-50 dark:bg-slate-900/50 rounded-lg border border-slate-100 dark:border-slate-800 text-xs font-mono text-slate-500 overflow-hidden relative group/code">
                        <div class="absolute top-1 right-2 opacity-0 group-hover/code:opacity-100 transition-opacity text-[10px] text-indigo-500 font-bold uppercase tracking-wide">Suspect Email</div>
                        <p class="line-clamp-3">${data.emailContent.substring(0, 200)}</p>
                    </div>
                `;
          }

          // Delete Button (Author Only)
          let deleteBtn = '';
          if (user && user.uid === data.authorId) {
            deleteBtn = `
                <button onclick="event.stopPropagation(); window.deletePost('${pid}')" class="text-slate-400 hover:text-red-500 transition-colors p-2" title="Delete Post">
                    <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                    </svg>
                </button>
             `;
          }

          const card = document.createElement('div');
          // Add cursor-pointer and hover effect
          card.className = "bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-5 shadow-sm hover:shadow-md transition-all cursor-pointer flex flex-col group relative";

          card.addEventListener('click', (e) => {
            // Ensure we don't trigger if text is selected or if interactive elements were clicked
            if (window.getSelection().toString().length > 0) return;
            console.log("Card clicked:", pid);
            if (window.openPostDetails) {
              window.openPostDetails(pid);
            } else {
              console.error("openPostDetails not found");
            }
          });

          card.innerHTML = `
                <div class="flex items-center justify-between mb-3">
                    <div class="flex flex-col">
                        <span class="text-xs font-semibold text-indigo-600 dark:text-indigo-400">@${data.authorName}</span>
                        <span class="text-[10px] text-slate-400">${data.timestamp ? new Date(data.timestamp.toDate()).toLocaleDateString() : 'Just now'}</span>
                    </div>
                    <div class="flex items-center gap-2">
                        ${riskBadge}
                    </div>
                </div>

                <h3 class="font-bold text-slate-800 dark:text-slate-100 text-lg leading-snug mb-2">${data.title}</h3>
                
                <p class="text-slate-600 dark:text-slate-400 text-sm line-clamp-3 mb-2">
                    ${data.description || ''}
                </p>

                ${contentSnippet}

                <div class="flex flex-wrap gap-2 my-3">
                    ${topicsHtml}
                </div>

                <div class="pt-4 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between mt-auto">
                    <div class="flex gap-4">
                        <button onclick="event.stopPropagation(); window.likePost('${pid}')" class="flex items-center gap-1.5 text-sm font-medium transition-colors ${liked ? 'text-red-500' : 'text-slate-500 hover:text-red-500'}">
                            <svg class="w-4 h-4 ${liked ? 'fill-current' : ''}" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4.318 6.318a4.5 4.5 0 000 6.364L12 20.364l7.682-7.682a4.5 4.5 0 00-6.364-6.364L12 7.636l-1.318-1.318a4.5 4.5 0 00-6.364 0z" />
                            </svg>
                            ${data.likes ? data.likes.length : 0}
                        </button>
                        <button onclick="event.stopPropagation(); window.toggleComments('${pid}')" class="flex items-center gap-1.5 text-sm font-medium text-slate-500 hover:text-indigo-500 transition-colors">
                            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
                            </svg>
                            ${data.comments || 0}
                        </button>
                    </div>
                    <div class="flex items-center gap-2">
                        ${deleteBtn}
                        <div class="relative group">
                            <button onclick="event.stopPropagation()" class="text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 p-2">
                                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z" />
                                </svg>
                            </button>
                            <!-- Share Tooltip -->
                            <div class="absolute bottom-full right-0 mb-2 w-48 bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-300 text-xs rounded-lg shadow-xl border border-slate-100 dark:border-slate-700 opacity-0 group-hover:opacity-100 pointer-events-none group-hover:pointer-events-auto transition-opacity z-10 overflow-hidden">
                                <div class="flex flex-col">
                                    <button onclick="window.shareSocial('wa', '${encodeURIComponent(data.title)}')" class="px-3 py-2 hover:bg-slate-50 dark:hover:bg-slate-700 text-left flex items-center gap-2">WhatsApp</button>
                                    <button onclick="window.shareSocial('tg', '${encodeURIComponent(data.title)}')" class="px-3 py-2 hover:bg-slate-50 dark:hover:bg-slate-700 text-left flex items-center gap-2">Telegram</button>
                                    <button onclick="window.shareSocial('li', '${encodeURIComponent(data.title)}')" class="px-3 py-2 hover:bg-slate-50 dark:hover:bg-slate-700 text-left flex items-center gap-2">LinkedIn</button>
                                    <button onclick="window.shareSocial('cp', '${encodeURIComponent(data.title)}')" class="px-3 py-2 hover:bg-slate-50 dark:hover:bg-slate-700 text-left flex items-center gap-2">Copy Link</button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Comments Section (Hidden by default) -->
                <div id="comments-${pid}" class="hidden mt-4 pt-4 border-t border-dashed border-slate-200 dark:border-slate-800">
                    <div id="comments-list-${pid}" class="space-y-3 mb-3 max-h-40 overflow-y-auto"></div>
                    <div class="flex gap-2">
                        <input type="text" id="comment-input-${pid}" class="flex-1 rounded-lg border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-xs px-3 py-2 focus:ring-1 focus:ring-indigo-500" placeholder="Write a comment...">
                        <button onclick="window.submitComment('${pid}')" class="p-2 rounded-lg bg-indigo-600 text-white hover:bg-indigo-700 transition">
                             <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" /></svg>
                        </button>
                    </div>
                </div>
            `;
          grid.appendChild(card);
        });
      });
  };

  window.deletePost = function (pid) {
    if (!confirm("Are you sure you want to delete this post?")) return;
    const user = firebase.auth().currentUser;
    if (!user) return alert("You must be logged in.");

    db.collection('posts').doc(pid).get().then(doc => {
      if (!doc.exists) return;
      if (doc.data().authorId !== user.uid) {
        alert("You can only delete your own posts.");
        return;
      }
      db.collection('posts').doc(pid).delete().then(() => {
        console.log("Post deleted");
        // Snapshot listener will update UI
      }).catch(err => alert("Error deleting post: " + err.message));
    });
  };


  window.likePost = function (pid) {
    const user = firebase.auth().currentUser;
    if (!user) return alert("Please login to like posts.");

    const postRef = db.collection('posts').doc(pid);

    db.runTransaction((transaction) => {
      return transaction.get(postRef).then((postDoc) => {
        if (!postDoc.exists) throw "Post does not exist!";
        const likes = postDoc.data().likes || [];
        if (likes.includes(user.uid)) {
          // Unlike
          transaction.update(postRef, { likes: firebase.firestore.FieldValue.arrayRemove(user.uid) });
        } else {
          // Like
          transaction.update(postRef, { likes: firebase.firestore.FieldValue.arrayUnion(user.uid) });
        }
      });
    }).catch(err => console.error("Like failed", err));
  };

  window.shareSocial = function (platform, text) {
    const url = window.location.href; // In real app, deep link to post
    let link = '';
    if (platform === 'wa') link = `https://wa.me/?text=${text}%20${url}`;
    if (platform === 'tg') link = `https://t.me/share/url?url=${url}&text=${text}`;
    if (platform === 'li') link = `https://www.linkedin.com/sharing/share-offsite/?url=${url}`; // LinkedIn text is limited

    if (platform === 'cp') {
      navigator.clipboard.writeText(`${decodeURIComponent(text)} - ${url}`);
      alert('Link copied to clipboard!');
    } else {
      window.open(link, '_blank');
    }
  };

  window.toggleComments = function (pid) {
    const el = document.getElementById(`comments-${pid}`);
    if (el.classList.contains('hidden')) {
      el.classList.remove('hidden');
      // Load comments
      window.loadComments(pid);
    } else {
      el.classList.add('hidden');
    }
  };

  window.loadComments = function (pid) {
    const list = document.getElementById(`comments-list-${pid}`);
    list.innerHTML = '<div class="text-xs text-slate-400 italic">Loading...</div>';

    db.collection('posts').doc(pid).collection('comments').orderBy('timestamp', 'asc').limit(20)
      .get().then(snap => {
        list.innerHTML = '';
        if (snap.empty) {
          list.innerHTML = '<div class="text-xs text-slate-400 italic">No comments yet.</div>';
          return;
        }
        snap.forEach(d => {
          const c = d.data();
          const item = document.createElement('div');
          item.className = "flex gap-2 text-xs";
          item.innerHTML = `<span class="font-bold text-slate-700 dark:text-slate-300">${c.authorName}:</span> <span class="text-slate-600 dark:text-slate-400">${c.text}</span>`;
          list.appendChild(item);
        });
      });
  };

  window.submitComment = function (pid) {
    const user = firebase.auth().currentUser;
    if (!user) return alert("Login to comment.");
    const input = document.getElementById(`comment-input-${pid}`);
    const text = input.value.trim();
    if (!text) return;

    const batch = db.batch();
    const postRef = db.collection('posts').doc(pid);
    const commentRef = postRef.collection('comments').doc();

    batch.set(commentRef, {
      text: text,
      authorId: user.uid,
      authorName: user.email.split('@')[0],
      timestamp: firebase.firestore.FieldValue.serverTimestamp()
    });

    // Increment counter (naive approach, strict atomic increment better but this is fine for demo)
    // Actually let's use a transaction for safety if we were strictly counting, but batch + FieldValue.increment is easier
    batch.update(postRef, {
      comments: firebase.firestore.FieldValue.increment(1)
    });

    batch.commit().then(() => {
      input.value = '';
      window.loadComments(pid); // reload
    });
  };

  // Share to Feed from Analyze Modal
  window.shareToFeed = function (reportJson) {
    const r = typeof reportJson === 'string' ? JSON.parse(reportJson) : reportJson;

    // Get text from analyze page if available, else generic placeholder
    let emailContent = '';
    const emailInput = document.getElementById('emailText');
    if (emailInput) emailContent = emailInput.value;

    const draft = {
      report: r,
      emailContent: emailContent
    };

    localStorage.setItem('pg_feed_draft', JSON.stringify(draft));
    window.location.href = 'feed.html';
  };


  // Logout 
  function initFirebaseAuthUI() {
    // ensure firebase & auth exist
    if (typeof firebase === 'undefined' || !firebase.auth) return;

    const logoutBtn = document.getElementById('logoutBtn');
    const loginLinks = document.querySelectorAll('a[href="login.html"]');

    firebase.auth().onAuthStateChanged(user => {
      if (user) {
        // USER LOGGED IN
        if (logoutBtn) logoutBtn.classList.remove('hidden');
        loginLinks.forEach(l => l.classList.add('hidden'));
      } else {
        // USER LOGGED OUT
        if (logoutBtn) logoutBtn.classList.add('hidden');
        loginLinks.forEach(l => l.classList.remove('hidden'));
      }
    });

    if (logoutBtn) {
      logoutBtn.addEventListener('click', () => {
        firebase.auth().signOut().then(() => {
          localStorage.removeItem('pg_user');
          window.location.href = 'login.html';
        });
      });
    }
  }


  // ---------------------------------------------------------
  // Global Auth Listener (Syncs UI across pages)
  // ---------------------------------------------------------

  // Wait for DOM to be ready before attaching listener that might manipulate DOM

  // We need to define renderRecent locally or expose it. 
  // Since initAnalyze.renderRecent is inside a closure, we should probably expose it or move it out.
  // Best approach: A global renderRecentIfAnalyzePage function.

  function updateRecentScansUI(user) {
    const recentList = document.getElementById('recentList');
    if (!recentList) return; // Not on analyze page

    if (user) {
      // User is logged in
      recentList.classList.remove('hidden');

      // Re-use logic to render list
      db.collection('users').doc(user.uid).collection('reports')
        .orderBy('date', 'desc')
        .limit(5)
        .onSnapshot((querySnapshot) => {
          const history = [];
          querySnapshot.forEach((doc) => {
            history.push({ id: doc.id, ...doc.data() });
          });

          if (history.length === 0) {
            recentList.innerHTML = `<li class="text-center text-slate-400 py-4 text-sm italic">No recent scans found.</li>`;
          } else {
            recentList.innerHTML = history.map(r => `
              <li class="p-3 bg-white dark:bg-slate-900 rounded-lg border border-slate-200 dark:border-slate-800 hover:border-indigo-500 transition cursor-pointer flex justify-between items-center group" onclick="window.openReportModal(${JSON.stringify(r).replace(/"/g, '&quot;')})">
                  <div class="truncate pr-4">
                      <div class="text-sm font-medium text-slate-700 dark:text-slate-200 truncate">${r.subject || 'No Subject'}</div>
                      <div class="text-xs text-slate-500">${new Date(r.date).toLocaleDateString()}</div>
                  </div>
                  <span class="text-xs px-2 py-1 rounded-full ${r.score > 70 ? 'bg-red-100 text-red-600' : (r.score > 40 ? 'bg-amber-100 text-amber-600' : 'bg-green-100 text-green-600')} font-bold whitespace-nowrap">${r.score}% Risk</span>
              </li>
            `).join('');
          }
        });
    } else {
      // User logged out
      recentList.innerHTML = '<li class="text-sm text-slate-500 text-center italic py-4">Login to save your scan history.</li>';
    }
  }

  // Auth State Changed
  if (typeof firebase !== 'undefined') {
    firebase.auth().onAuthStateChanged(user => {
      // 1. Update Header Buttons
      const loginBtn = document.querySelector('a[href="login.html"]');
      const signupBtn = document.querySelector('a[href="signup.html"]');
      const logoutBtn = document.getElementById('logoutBtn');

      if (user) {
        if (loginBtn) loginBtn.classList.add('hidden');
        if (signupBtn) signupBtn.classList.add('hidden');
        if (logoutBtn) logoutBtn.classList.remove('hidden');
      } else {
        if (loginBtn) loginBtn.classList.remove('hidden');
        if (signupBtn) signupBtn.classList.remove('hidden');
        if (logoutBtn) logoutBtn.classList.add('hidden');
      }

      // 2. Update Recent Scans (if on Analyze page)
      updateRecentScansUI(user);

      // 3. Update Reports Table (if on Reports page)
      if (document.getElementById('reportsTable')) {
        // Re-init reports to load data
        // We can just call initReports again if it handles auth check, 
        // but let's be safe and let initReports handle it on load, 
        // and this refresher handle updates.
        const w = window;
        if (w.initReportsRefresher) w.initReportsRefresher(user);
      }
    });
  }


  // ---------------------------------------------------------
  // Report Actions (Global)
  // ---------------------------------------------------------
  window.deleteReport = function (reportId) {
    if (!confirm("Are you sure you want to delete this report?")) return;

    const user = firebase.auth().currentUser;
    if (!user) return;

    // Delete from Firestore
    db.collection('users').doc(user.uid).collection('reports').doc(reportId).delete()
      .then(() => {
        console.log("Report deleted successfully!");
        if (window.closeReportModal) window.closeReportModal();
      })
      .catch((error) => {
        console.error("Error removing report: ", error);
      });
  };

  window.downloadReport = function (reportJson) {
    const r = typeof reportJson === 'string' ? JSON.parse(reportJson) : reportJson;

    // Create a hidden temporary container for the PDF
    const element = document.createElement('div');
    element.style.width = '800px';
    element.style.padding = '40px';
    element.style.fontFamily = "'Inter', sans-serif";
    element.style.color = '#1e293b';
    element.style.background = '#ffffff';

    // Layout
    element.innerHTML = `
        < div style = "border-bottom: 2px solid #e2e8f0; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: start;" >
          <div>
              <h1 style="font-size: 24px; font-weight: bold; margin: 0; color: #0f172a;">PhishGuard Security Report</h1>
              <p style="margin: 5px 0 0; color: #64748b; font-size: 14px;">Automated AI Email Analysis</p>
          </div>
          <div style="text-align: right;">
              <div style="font-size: 12px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600;">Scan Date</div>
              <div style="font-weight: 500; font-size: 14px;">${new Date(r.date).toLocaleString()}</div>
          </div>
      </div >

      <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px; margin-bottom: 30px; display: flex; align-items: center; gap: 20px;">
          <div style="width: 80px; height: 80px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 24px; font-weight: bold; border: 4px solid 
              ${r.score > 70 ? '#ef4444' : (r.score > 40 ? '#f59e0b' : '#22c55e')}; background: white;">
              ${r.score}%
          </div>
          <div>
              <div style="font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; margin-bottom: 4px;">Risk Assessment</div>
              <div style="font-size: 20px; font-weight: bold; color: ${r.score > 70 ? '#ef4444' : (r.score > 40 ? '#f59e0b' : '#22c55e')}">
                  ${r.score > 70 ? 'High Risk' : (r.score > 40 ? 'Medium Risk' : 'Low Risk')}
              </div>
              <div style="font-size: 14px; color: #64748b; margin-top: 4px;">Type: <strong>${r.type}</strong></div>
          </div>
      </div>

      <div style="margin-bottom: 30px;">
          <h3 style="font-size: 16px; font-weight: bold; border-left: 4px solid #6366f1; padding-left: 12px; margin-bottom: 12px; color: #0f172a;">AI Summary</h3>
          <div style="background: #eef2ff; padding: 16px; border-radius: 8px; color: #334155; font-size: 14px; line-height: 1.6;">
              ${r.summary}
          </div>
      </div>

      <div style="margin-bottom: 30px;">
          <h3 style="font-size: 16px; font-weight: bold; border-left: 4px solid #6366f1; padding-left: 12px; margin-bottom: 12px; color: #0f172a;">Subject Line</h3>
          <div style="background: white; border: 1px solid #e2e8f0; padding: 12px; border-radius: 8px; color: #334155; font-size: 14px;">
              ${r.subject}
          </div>
      </div>

      <div>
          <h3 style="font-size: 16px; font-weight: bold; border-left: 4px solid #6366f1; padding-left: 12px; margin-bottom: 12px; color: #0f172a;">Key Findings</h3>
          <ul style="list-style: none; padding: 0; margin: 0;">
              ${(r.findings && r.findings.length) ? r.findings.map(f => `
                  <li style="margin-bottom: 8px; padding-left: 20px; position: relative; color: #475569; font-size: 14px;">
                      <span style="position: absolute; left: 0; top: 6px; width: 6px; height: 6px; background: #ef4444; border-radius: 50%;"></span>
                      ${f}
                  </li>
              `).join('') : '<li style="color: #94a3b8; font-style: italic;">No specific threat indicators found.</li>'}
          </ul>
      </div>
      
      <div style="margin-top: 50px; border-top: 1px solid #e2e8f0; padding-top: 20px; text-align: center; color: #94a3b8; font-size: 12px;">
          Generated by PhishGuard AI • ${new Date().getFullYear()}
      </div>
      `;

    // Must append to body to render, then remove
    // But html2pdf can handle element even if not in DOM? 
    // Ideally put it in a hidden container off-screen
    const container = document.createElement('div');
    container.style.position = 'absolute';
    container.style.left = '-9999px';
    container.style.top = '0';
    container.appendChild(element);
    document.body.appendChild(container);

    if (typeof html2pdf !== 'undefined') {
      const opt = {
        margin: 0.5,
        filename: `PhishGuard_Report_${new Date().toISOString().slice(0, 10)}.pdf`,
        image: { type: 'jpeg', quality: 0.98 },
        html2canvas: { scale: 2, useCORS: true, logging: false },
        jsPDF: { unit: 'in', format: 'a4', orientation: 'portrait' }
      };
      html2pdf().set(opt).from(element).save().then(() => {
        document.body.removeChild(container);
      }).catch(err => {
        console.error(err);
        alert("PDF Generation Error: " + err.message);
        document.body.removeChild(container);
      });
    } else {
      alert("PDF library loading... please try again.");
      document.body.removeChild(container);
    }
  };

  window.shareReport = function (reportJson) {
    const r = typeof reportJson === 'string' ? JSON.parse(reportJson) : reportJson;
    const text = `PhishGuard Alert: I scanned an email titled "${r.subject}" and it blocked a ${r.score}% risk threat! Stay safe with PhishGuard.`;

    navigator.clipboard.writeText(text).then(() => {
      alert("Generic report summary copied to clipboard!");
    }).catch(err => console.error(err));
  };




  // ---------------------------------------------------------
  // Init when DOM Ready
  // ---------------------------------------------------------
  document.addEventListener('DOMContentLoaded', function () {
    markNav();
    initMobileMenu();
    initNavbarScroll();
    initHome();

    // Init specific pages
    if (document.getElementById('emailText')) initAnalyze();
    if (document.getElementById('feedGrid')) initFeed();
    if (document.getElementById('reportsTable')) initReports();

    initFirebaseAuthUI();
  });

})();
