const API = '/api';

/* ============ SESSION ============ */
let token = null;
let currentUser = null;
let editingId = null;

try {
  token = localStorage.getItem('task7Token');
  currentUser = JSON.parse(localStorage.getItem('task7User'));
} catch (e) {}

function saveSession(newToken, user) {
  token = newToken;
  currentUser = user;
  try {
    localStorage.setItem('task7Token', newToken);
    localStorage.setItem('task7User', JSON.stringify(user));
  } catch (e) {}
}

function clearSession() {
  token = null;
  currentUser = null;
  try {
    localStorage.removeItem('task7Token');
    localStorage.removeItem('task7User');
  } catch (e) {}
}

/* ============ ELEMENTS ============ */
const authView = document.getElementById('authView');
const appView = document.getElementById('appView');
const userBox = document.getElementById('userBox');
const userLabel = document.getElementById('userLabel');
const roleBadge = document.getElementById('roleBadge');
const adminPanel = document.getElementById('adminPanel');
const ownerHeader = document.getElementById('ownerHeader');

const tabLogin = document.getElementById('tabLogin');
const tabRegister = document.getElementById('tabRegister');
const loginForm = document.getElementById('loginForm');
const registerForm = document.getElementById('registerForm');
const authMessage = document.getElementById('authMessage');

const form = document.getElementById('studentForm');
const nameInput = document.getElementById('name');
const emailInput = document.getElementById('email');
const courseInput = document.getElementById('course');
const saveBtn = document.getElementById('saveBtn');
const cancelBtn = document.getElementById('cancelBtn');
const formTitle = document.getElementById('formTitle');
const tableBody = document.getElementById('studentTable');
const searchInput = document.getElementById('searchInput');
const messageBox = document.getElementById('messageBox');
const emptyState = document.getElementById('emptyState');

const weatherForm = document.getElementById('weatherForm');
const cityInput = document.getElementById('cityInput');
const weatherBtn = document.getElementById('weatherBtn');
const weatherResult = document.getElementById('weatherResult');

/* ============ HELPERS ============ */
const timers = new Map();
function showMessage(box, text, type) {
  box.textContent = text;
  box.className = 'alert alert-' + type;
  clearTimeout(timers.get(box));
  timers.set(box, setTimeout(() => box.classList.add('d-none'), 4000));
}

// Talks to the API, sends the token, and turns errors into readable messages
async function request(path, options = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = 'Bearer ' + token;

  const response = await fetch(API + path, Object.assign({}, options, { headers }));

  let data = {};
  try {
    data = await response.json();
  } catch (e) {}

  if (!response.ok) {
    if (response.status === 401 && token) {
      logout('Your session expired. Please log in again.');
    }
    let message = (data.errors || ['Something went wrong.']).join(' ');
    if (response.status === 429) {
      const wait = response.headers.get('Retry-After');
      if (wait) message += ' (try again in ' + wait + ' seconds)';
    }
    throw new Error(message);
  }
  return data;
}

/* ============ SHOW THE RIGHT VIEW ============ */
function showView() {
  const loggedIn = Boolean(token && currentUser);
  authView.classList.toggle('d-none', loggedIn);
  appView.classList.toggle('d-none', !loggedIn);
  userBox.classList.toggle('d-none', !loggedIn);

  if (!loggedIn) return;

  const isAdmin = currentUser.role === 'admin';
  userLabel.textContent = currentUser.username;
  roleBadge.textContent = currentUser.role;
  roleBadge.className = 'badge ' + (isAdmin ? 'bg-danger' : 'bg-info text-dark');
  adminPanel.classList.toggle('d-none', !isAdmin);
  ownerHeader.classList.toggle('d-none', !isAdmin);

  loadStudents();
  if (isAdmin) loadUsers();
}

function logout(message) {
  clearSession();
  resetForm();
  weatherResult.innerHTML = '';
  showView();
  if (message) showMessage(authMessage, message, 'warning');
}

document.getElementById('logoutBtn').addEventListener('click', () => logout('You have been logged out.'));

/* ============ OAUTH REDIRECT (back from GitHub) ============ */
// The server sends the user back as  /#token=...  or  /#error=...
async function handleOAuthRedirect() {
  const params = new URLSearchParams(location.hash.slice(1));
  const newToken = params.get('token');
  const error = params.get('error');
  if (!newToken && !error) return;

  history.replaceState(null, '', location.pathname); // remove the token from the address bar

  if (error) {
    showMessage(authMessage, error, 'danger');
    return;
  }

  try {
    token = newToken;
    const user = await request('/auth/me');
    saveSession(newToken, user);
  } catch (err) {
    clearSession();
    showMessage(authMessage, 'GitHub login failed: ' + err.message, 'danger');
  }
}

/* ============ LOGIN / REGISTER ============ */
function switchTab(showLogin) {
  tabLogin.classList.toggle('active', showLogin);
  tabRegister.classList.toggle('active', !showLogin);
  loginForm.classList.toggle('d-none', !showLogin);
  registerForm.classList.toggle('d-none', showLogin);
  authMessage.classList.add('d-none');
}
tabLogin.addEventListener('click', () => switchTab(true));
tabRegister.addEventListener('click', () => switchTab(false));

loginForm.addEventListener('submit', async e => {
  e.preventDefault();
  try {
    const data = await request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        username: document.getElementById('loginUsername').value,
        password: document.getElementById('loginPassword').value
      })
    });
    loginForm.reset();
    saveSession(data.token, data.user);
    showView();
  } catch (err) {
    showMessage(authMessage, err.message, 'danger');
  }
});

registerForm.addEventListener('submit', async e => {
  e.preventDefault();
  try {
    const data = await request('/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        username: document.getElementById('regUsername').value,
        email: document.getElementById('regEmail').value,
        password: document.getElementById('regPassword').value
      })
    });
    registerForm.reset();
    saveSession(data.token, data.user);
    showView();
  } catch (err) {
    showMessage(authMessage, err.message, 'danger');
  }
});

/* ============ WEATHER (external API through our server) ============ */
function renderWeatherMessage(text, type) {
  weatherResult.innerHTML = '';
  const box = document.createElement('div');
  box.className = 'alert alert-' + type;
  box.textContent = text;
  weatherResult.appendChild(box);
}

function renderWeather(w) {
  weatherResult.innerHTML = '';
  const box = document.createElement('div');
  box.className = 'alert alert-info';

  const title = document.createElement('h5');
  title.textContent = w.city + (w.country ? ', ' + w.country : '');

  const lines = [
    'Condition: ' + w.description,
    'Temperature: ' + w.temperature + ' °C',
    'Humidity: ' + w.humidity + ' %',
    'Wind speed: ' + w.windSpeed + ' km/h'
  ];

  box.appendChild(title);
  lines.forEach(text => {
    const p = document.createElement('p');
    p.className = 'mb-1';
    p.textContent = text;
    box.appendChild(p);
  });

  if (w.cached) {
    const small = document.createElement('small');
    small.className = 'text-muted';
    small.textContent = '(served from the server cache)';
    box.appendChild(small);
  }
  weatherResult.appendChild(box);
}

weatherForm.addEventListener('submit', async e => {
  e.preventDefault();
  const city = cityInput.value.trim();
  if (city.length < 2) {
    renderWeatherMessage('Please enter a city name.', 'warning');
    return;
  }

  weatherBtn.disabled = true;
  weatherBtn.textContent = 'Loading...';
  try {
    const weather = await request('/weather?city=' + encodeURIComponent(city));
    renderWeather(weather);
  } catch (err) {
    renderWeatherMessage(err.message, 'danger');
  } finally {
    weatherBtn.disabled = false;
    weatherBtn.textContent = 'Get Weather';
  }
});

/* ============ READ students ============ */
async function loadStudents() {
  try {
    const query = encodeURIComponent(searchInput.value.trim());
    const students = await request('/students?search=' + query);
    renderTable(students);
  } catch (err) {
    showMessage(messageBox, 'Could not load students: ' + err.message, 'danger');
  }
}

function renderTable(students) {
  const isAdmin = currentUser && currentUser.role === 'admin';
  tableBody.innerHTML = '';
  emptyState.classList.toggle('d-none', students.length > 0);
  document.getElementById('totalCount').textContent = students.length;

  students.forEach(s => {
    const row = document.createElement('tr');
    if (s.id === editingId) row.classList.add('editing');

    const values = [s.id, s.name, s.email, s.course];
    if (isAdmin) values.push(s.owner);

    values.forEach(value => {
      const cell = document.createElement('td');
      cell.textContent = value;
      row.appendChild(cell);
    });

    const actions = document.createElement('td');
    actions.className = 'text-end';

    const editBtn = document.createElement('button');
    editBtn.className = 'btn btn-sm btn-outline-primary me-2';
    editBtn.textContent = 'Edit';
    editBtn.addEventListener('click', () => startEdit(s));

    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'btn btn-sm btn-outline-danger';
    deleteBtn.textContent = 'Delete';
    deleteBtn.addEventListener('click', () => deleteStudent(s));

    actions.append(editBtn, deleteBtn);
    row.appendChild(actions);
    tableBody.appendChild(row);
  });
}

/* ============ ADMIN: list of users ============ */
async function loadUsers() {
  try {
    const users = await request('/admin/users');
    const body = document.getElementById('userTable');
    body.innerHTML = '';

    users.forEach(u => {
      const row = document.createElement('tr');
      [u.id, u.username, u.email, u.role, u.studentCount].forEach(value => {
        const cell = document.createElement('td');
        cell.textContent = value;
        row.appendChild(cell);
      });
      body.appendChild(row);
    });
  } catch (err) {
    showMessage(messageBox, err.message, 'danger');
  }
}

/* ============ CREATE and UPDATE ============ */
form.addEventListener('submit', async e => {
  e.preventDefault();

  const payload = JSON.stringify({
    name: nameInput.value,
    email: emailInput.value,
    course: courseInput.value
  });

  saveBtn.disabled = true;
  try {
    if (editingId === null) {
      await request('/students', { method: 'POST', body: payload });
      showMessage(messageBox, 'Student added successfully!', 'success');
    } else {
      await request('/students/' + editingId, { method: 'PUT', body: payload });
      showMessage(messageBox, 'Student updated successfully!', 'success');
    }
    resetForm();
    loadStudents();
    if (currentUser && currentUser.role === 'admin') loadUsers();
  } catch (err) {
    showMessage(messageBox, err.message, 'danger');
  } finally {
    saveBtn.disabled = false;
  }
});

function startEdit(student) {
  editingId = student.id;
  nameInput.value = student.name;
  emailInput.value = student.email;
  courseInput.value = student.course;
  formTitle.textContent = 'Edit Student #' + student.id;
  saveBtn.textContent = 'Update Student';
  cancelBtn.classList.remove('d-none');
  window.scrollTo({ top: 0, behavior: 'smooth' });
  loadStudents();
}

function resetForm() {
  editingId = null;
  form.reset();
  formTitle.textContent = 'Add Student';
  saveBtn.textContent = 'Add Student';
  cancelBtn.classList.add('d-none');
}

cancelBtn.addEventListener('click', () => {
  resetForm();
  loadStudents();
});

/* ============ DELETE ============ */
async function deleteStudent(student) {
  if (!confirm('Delete ' + student.name + '?')) return;
  try {
    await request('/students/' + student.id, { method: 'DELETE' });
    showMessage(messageBox, 'Student deleted.', 'success');
    if (editingId === student.id) resetForm();
    loadStudents();
    if (currentUser && currentUser.role === 'admin') loadUsers();
  } catch (err) {
    showMessage(messageBox, err.message, 'danger');
  }
}

/* ============ SEARCH ============ */
let searchTimer;
searchInput.addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(loadStudents, 300);
});

/* ============ START ============ */
handleOAuthRedirect().then(showView);