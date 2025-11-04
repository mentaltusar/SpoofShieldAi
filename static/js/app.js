function dismissLoader() {
    const loader = document.getElementById('loader-wrapper');
    const mainContent = document.getElementById('main-content');

    // Hide loader
    if (loader) {
        loader.style.opacity = '0';
        setTimeout(() => {
            loader.style.display = 'none';
        }, 500); // Match CSS transition time
    }

    // Show main content
    if (mainContent) {
        mainContent.style.opacity = '1';
    }
}

// Function to set up the scroll animations
function setupScrollAnimations() {
    const observer = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                // When element enters view, add the class to start the animation
                entry.target.classList.add('is-visible');
                observer.unobserve(entry.target);
            }
        });
    }, {
        rootMargin: '0px',
        threshold: 0.1 // Triggers when 10% of the element is visible
    });

    document.querySelectorAll('.animate-on-scroll').forEach(el => {
        observer.observe(el);
    });
}


document.addEventListener('DOMContentLoaded', () => {
    // --- Initial Loader Logic ---
    const logoVideo = document.getElementById('logo-animation-loader');

    // Determine when to dismiss the loader: either after a fixed time (fallback)
    // or when the video metadata loads (more reliable).
    const FIXED_LOAD_TIME = 2000; // 2 seconds minimum wait

    if (logoVideo) {
        // Option 1: Wait for video to be ready, then wait an extra second (to let the animation play)
        logoVideo.onloadeddata = () => {
             setTimeout(dismissLoader, 1000); // 1 second play time after data loads
        };
        // Fallback: If video takes too long to load, dismiss after fixed time
        setTimeout(dismissLoader, FIXED_LOAD_TIME);
    } else {
        // If no video element exists, just dismiss after a very short time
        setTimeout(dismissLoader, 100);
    }

    // --- Setup Scroll Animations ---
    setupScrollAnimations();
});