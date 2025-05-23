// cryptography_app/static/js/script.js

document.addEventListener('DOMContentLoaded', () => {
    // Theme toggling functionality
    const themeToggle = document.getElementById('themeToggle');
    const htmlElement = document.documentElement;
    
    // Apply the theme based on preference
    const applyTheme = (theme) => {
        if (theme === 'dark') {
            htmlElement.classList.remove('light');
            htmlElement.classList.add('dark');
            localStorage.setItem('theme', 'dark');
            
            // Update toggle icon if it exists
            const toggleIcon = themeToggle?.querySelector('svg');
            if (toggleIcon) {
                toggleIcon.innerHTML = `
                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="theme-toggle-icon">
                    <path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"></path>
                </svg>`;
            }
        } else {
            htmlElement.classList.add('light');
            htmlElement.classList.remove('dark');
            localStorage.setItem('theme', 'light');
            
            // Update toggle icon if it exists
            const toggleIcon = themeToggle?.querySelector('svg');
            if (toggleIcon) {
                toggleIcon.innerHTML = `
                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="theme-toggle-icon">
                    <circle cx="12" cy="12" r="4"></circle>
                    <path d="M12 2v2"></path>
                    <path d="M12 20v2"></path>
                    <path d="m4.93 4.93 1.41 1.41"></path>
                    <path d="m17.66 17.66 1.41 1.41"></path>
                    <path d="M2 12h2"></path>
                    <path d="M20 12h2"></path>
                    <path d="m6.34 17.66-1.41 1.41"></path>
                    <path d="m19.07 4.93-1.41 1.41"></path>
                </svg>`;
            }
        }
    };

    // Initialize theme
    const getInitialTheme = () => {
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme) {
            return savedTheme;
        }
        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    };
    
    // Apply initial theme
    applyTheme(getInitialTheme());
    
    // Toggle theme when button is clicked
    if (themeToggle) {
        themeToggle.addEventListener('click', () => {
            const currentTheme = htmlElement.classList.contains('light') ? 'dark' : 'light';
            applyTheme(currentTheme);
        });
    }
    
    // Create theme toggle if it doesn't exist
    if (!themeToggle) {
        const toggleWrapper = document.createElement('div');
        toggleWrapper.id = 'themeToggle';
        toggleWrapper.className = 'theme-toggle-wrapper';
        toggleWrapper.setAttribute('title', 'Toggle light/dark theme');
        
        // Set initial icon based on current theme
        const isDark = !htmlElement.classList.contains('light');
        toggleWrapper.innerHTML = isDark ? 
            `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="theme-toggle-icon">
                <path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"></path>
            </svg>` : 
            `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="theme-toggle-icon">
                <circle cx="12" cy="12" r="4"></circle>
                <path d="M12 2v2"></path>
                <path d="M12 20v2"></path>
                <path d="m4.93 4.93 1.41 1.41"></path>
                <path d="m17.66 17.66 1.41 1.41"></path>
                <path d="M2 12h2"></path>
                <path d="M20 12h2"></path>
                <path d="m6.34 17.66-1.41 1.41"></path>
                <path d="m19.07 4.93-1.41 1.41"></path>
            </svg>`;
        
        document.body.appendChild(toggleWrapper);
        
        toggleWrapper.addEventListener('click', () => {
            const currentTheme = htmlElement.classList.contains('light') ? 'dark' : 'light';
            applyTheme(currentTheme);
        });
    }

    // Other existing JS functionality
    window.toggleInputFields = function(cipherPrefix, selectedType) {
        const textArea = document.getElementById(`text_input_${cipherPrefix}_area`);
        const fileArea = document.getElementById(`file_input_${cipherPrefix}_area`);
        const textInput = document.getElementById(`input_text_${cipherPrefix}`);
        const fileInput = document.getElementById(`input_file_${cipherPrefix}`);

        if (!textArea || !fileArea) return;

        if (selectedType === 'text') {
            textArea.style.display = 'block';
            fileArea.style.display = 'none';
            textInput.required = true;
            if (fileInput) fileInput.required = false;
        } else {
            textArea.style.display = 'none';
            fileArea.style.display = 'block';
            textInput.required = false;
            if (fileInput) fileInput.required = true;
        }
    };

    // Initialize Lucide icons
    if (typeof lucide !== 'undefined' && typeof lucide.createIcons === 'function') {
        lucide.createIcons();
    }
});
