// cryptography_app/static/js/script.js

document.addEventListener('DOMContentLoaded', () => {
    // Dark Mode Toggle
    const darkModeToggle = document.getElementById('darkModeToggle');
    const sunIcon = darkModeToggle ? darkModeToggle.querySelector('.sun-icon') : null;
    const moonIcon = darkModeToggle ? darkModeToggle.querySelector('.moon-icon') : null;
    const htmlElement = document.documentElement;

    const applyDarkMode = (isDark) => {
        if (isDark) {
            htmlElement.classList.add('dark');
            if (sunIcon) sunIcon.classList.add('hidden');
            if (moonIcon) moonIcon.classList.remove('hidden');
        } else {
            htmlElement.classList.remove('dark');
            if (sunIcon) sunIcon.classList.remove('hidden');
            if (moonIcon) moonIcon.classList.add('hidden');
        }
    };

    // Check local storage for saved preference
    let currentIsDark;
    const storedPreference = localStorage.getItem('darkMode');

    if (storedPreference !== null) {
        currentIsDark = storedPreference === 'true';
    } else {
        currentIsDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    }
    applyDarkMode(currentIsDark);

    if (darkModeToggle) {
        darkModeToggle.addEventListener('click', () => {
            const isDark = htmlElement.classList.toggle('dark');
            localStorage.setItem('darkMode', isDark);
            applyDarkMode(isDark);
        });
    }
    
    // Initialize Lucide icons if not already done by inline script
    if (typeof lucide !== 'undefined' && typeof lucide.createIcons === 'function') {
        lucide.createIcons();
    }

    // Function to toggle input fields based on radio button selection
    window.toggleInputFields = function(cipherPrefix, selectedType) {
        const textArea = document.getElementById(`text_input_${cipherPrefix}_area`);
        const fileArea = document.getElementById(`file_input_${cipherPrefix}_area`);
        const textInput = document.getElementById(`input_text_${cipherPrefix}`);
        const fileInput = document.getElementById(`input_file_${cipherPrefix}`);

        if (!textArea || !fileArea) return;

        if (selectedType === 'text') {
            textArea.classList.remove('hidden');
            fileArea.classList.add('hidden');
            if(textInput) textInput.required = true;
            if(fileInput) fileInput.required = false;
        } else { // file
            textArea.classList.add('hidden');
            fileArea.classList.remove('hidden');
            if(textInput) textInput.required = false;
            if(fileInput) fileInput.required = true;
        }
    }

    // Initialize input fields visibility for all relevant pages
    const prefixes = ['xor', 'caesar', 'block', 'hash']; // Add 'block' if it uses the same pattern
    prefixes.forEach(prefix => {
        const selectedRadio = document.querySelector(`input[name="input_type_${prefix}"]:checked`);
        if (selectedRadio) {
            toggleInputFields(prefix, selectedRadio.value);
        }
    });

    // Add typing effect to specific elements
    const typingElements = document.querySelectorAll('.typing-effect');
    typingElements.forEach(el => {
        const text = el.getAttribute('data-text');
        if (text) {
            typeWriter(el, text);
        }
    });

    // Matrix background effect (cmatrix style)
    const matrixBg = document.getElementById("matrix-bg");
    
    // Set density based on screen size
    const screenWidth = window.innerWidth;
    const columnCount = Math.floor(screenWidth / 20); // Controls density
    
    function createMatrixColumn() {
      const column = document.createElement("div");
      column.classList.add("matrix-text");
      
      // Generate matrix characters
      const length = 15 + Math.floor(Math.random() * 25);
      const chars = "01アイウエオカキクケコサシスセソタチツテト"; // Mix of digits and katakana
      
      // Create character spans with varying opacity
      let html = '';
      for (let i = 0; i < length; i++) {
        const char = chars.charAt(Math.floor(Math.random() * chars.length));
        const isLead = i === 0; // First character is the "lead"
        html += `<span class="matrix-char ${isLead ? 'lead' : ''}">${char}</span><br>`;
      }
      column.innerHTML = html;
      
      // Position and speed
      column.style.left = `${Math.random() * 100}%`;
      column.style.animationDuration = `${8 + Math.random() * 10}s`;
      column.style.fontSize = `${10 + Math.random() * 4}px`;
      column.style.opacity = `${0.4 + Math.random() * 0.4}`;
      
      matrixBg.appendChild(column);
      
      // Remove after animation
      setTimeout(() => {
        column.remove();
      }, 20000);
    }
    
    // Create initial columns - denser than before
    for (let i = 0; i < columnCount; i++) {
      setTimeout(() => {
        createMatrixColumn();
      }, i * 100); // Stagger the creation
    }
    
    // Add new columns periodically at random intervals
    setInterval(() => {
      if (matrixBg.childElementCount < columnCount * 1.5) {
        createMatrixColumn();
      }
    }, 800);
});

// Add this to your script.js file

function typeWriter(element, text, speed = 50, callback = null) {
    let i = 0;
    element.innerHTML = '';
    
    function type() {
        if (i < text.length) {
            element.innerHTML += text.charAt(i);
            i++;
            setTimeout(type, speed);
        } else if (callback) {
            callback();
        }
    }
    
    type();
}
