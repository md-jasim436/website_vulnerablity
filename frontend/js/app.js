// Common Application Utilities & Navigation

document.addEventListener('DOMContentLoaded', () => {
  highlightActiveNavLink();
});

export function highlightActiveNavLink() {
  const currentPath = window.location.pathname;
  const navLinks = document.querySelectorAll('.nav-link');
  
  navLinks.forEach(link => {
    const href = link.getAttribute('href');
    if (href === currentPath || (currentPath === '/' && (href === '/index.html' || href === '/' || href === 'index.html'))) {
      link.classList.add('active');
    } else if (href && currentPath.endsWith(href)) {
      link.classList.add('active');
    } else {
      link.classList.remove('active');
    }
  });
}

export function showToast(message, type = 'info') {
  let toastContainer = document.getElementById('toast-container');
  if (!toastContainer) {
    toastContainer = document.createElement('div');
    toastContainer.id = 'toast-container';
    toastContainer.style.position = 'fixed';
    toastContainer.style.bottom = '24px';
    toastContainer.style.right = '24px';
    toastContainer.style.zIndex = '9999';
    toastContainer.style.display = 'flex';
    toastContainer.style.flexDirection = 'column';
    toastContainer.style.gap = '10px';
    document.body.appendChild(toastContainer);
  }

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.style.padding = '12px 20px';
  toast.style.borderRadius = '8px';
  toast.style.color = '#FFFFFF';
  toast.style.fontSize = '0.9rem';
  toast.style.fontWeight = '500';
  toast.style.boxShadow = '0 4px 16px rgba(0,0,0,0.3)';
  toast.style.transition = 'all 0.3s ease';
  toast.style.opacity = '0';
  toast.style.transform = 'translateY(10px)';

  if (type === 'error') {
    toast.style.backgroundColor = '#EF4444';
  } else if (type === 'success') {
    toast.style.backgroundColor = '#10B981';
  } else if (type === 'warning') {
    toast.style.backgroundColor = '#F59E0B';
  } else {
    toast.style.backgroundColor = '#0EA5E9';
  }

  toast.textContent = message;
  toastContainer.appendChild(toast);

  requestAnimationFrame(() => {
    toast.style.opacity = '1';
    toast.style.transform = 'translateY(0)';
  });

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

export function formatDateTime(isoString) {
  if (!isoString) return 'N/A';
  try {
    const d = new Date(isoString);
    return d.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  } catch (e) {
    return isoString;
  }
}
