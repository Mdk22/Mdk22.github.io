(() => {
    "use strict";

    const images = Array.from(
        document.querySelectorAll('.post-content img[data-evidence-lightbox="true"]')
    );

    if (!images.length || typeof HTMLDialogElement === "undefined") {
        return;
    }

    const dialog = document.createElement("dialog");
    dialog.className = "evidence-lightbox";
    dialog.setAttribute("aria-label", "Evidence image viewer");
    dialog.setAttribute("aria-describedby", "evidence-lightbox-caption");
    dialog.innerHTML = `
        <div class="evidence-lightbox__shell">
            <header class="evidence-lightbox__header">
                <span class="evidence-lightbox__counter" aria-live="polite"></span>
                <span class="evidence-lightbox__hint">Click image to inspect full size</span>
                <button class="evidence-lightbox__close" type="button" aria-label="Close image viewer">&times;</button>
            </header>
            <div class="evidence-lightbox__stage">
                <button class="evidence-lightbox__nav evidence-lightbox__nav--previous" type="button" aria-label="Previous image">&#8249;</button>
                <img class="evidence-lightbox__image" alt="">
                <button class="evidence-lightbox__nav evidence-lightbox__nav--next" type="button" aria-label="Next image">&#8250;</button>
            </div>
            <p class="evidence-lightbox__caption" id="evidence-lightbox-caption"></p>
        </div>`;

    document.body.appendChild(dialog);

    const lightboxImage = dialog.querySelector(".evidence-lightbox__image");
    const caption = dialog.querySelector(".evidence-lightbox__caption");
    const counter = dialog.querySelector(".evidence-lightbox__counter");
    const closeButton = dialog.querySelector(".evidence-lightbox__close");
    const previousButton = dialog.querySelector(".evidence-lightbox__nav--previous");
    const nextButton = dialog.querySelector(".evidence-lightbox__nav--next");

    let currentIndex = 0;
    let returnFocus = null;

    const updateImage = (index) => {
        currentIndex = (index + images.length) % images.length;
        const sourceImage = images[currentIndex];
        const source = sourceImage.dataset.lightboxSrc || sourceImage.currentSrc || sourceImage.src;
        const description = sourceImage.alt || `Evidence image ${currentIndex + 1}`;
        const figureCaption = sourceImage.closest("figure")?.querySelector("figcaption")?.textContent?.trim();
        const adjacentText = sourceImage.parentElement?.nextElementSibling?.textContent?.trim();
        const adjacentCaption = adjacentText?.startsWith("Figure ") ? adjacentText : "";

        lightboxImage.classList.remove("is-zoomed");
        lightboxImage.src = source;
        lightboxImage.alt = description;
        caption.textContent = figureCaption || adjacentCaption || description;
        counter.textContent = `${currentIndex + 1} / ${images.length}`;

        const hasMultipleImages = images.length > 1;
        previousButton.hidden = !hasMultipleImages;
        nextButton.hidden = !hasMultipleImages;
    };

    const openLightbox = (index, trigger) => {
        returnFocus = trigger;
        updateImage(index);

        if (!dialog.open) {
            dialog.showModal();
            document.body.classList.add("evidence-lightbox-open");
        }

        closeButton.focus({ preventScroll: true });
    };

    const closeLightbox = () => {
        if (dialog.open) {
            dialog.close();
        }
    };

    images.forEach((image, index) => {
        image.addEventListener("click", () => openLightbox(index, image));
        image.addEventListener("keydown", (event) => {
            if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                openLightbox(index, image);
            }
        });
    });

    closeButton.addEventListener("click", closeLightbox);
    previousButton.addEventListener("click", () => updateImage(currentIndex - 1));
    nextButton.addEventListener("click", () => updateImage(currentIndex + 1));

    lightboxImage.addEventListener("click", () => {
        lightboxImage.classList.toggle("is-zoomed");
    });

    dialog.addEventListener("click", (event) => {
        if (event.target === dialog) {
            closeLightbox();
        }
    });

    dialog.addEventListener("close", () => {
        document.body.classList.remove("evidence-lightbox-open");
        lightboxImage.classList.remove("is-zoomed");
        lightboxImage.removeAttribute("src");

        if (returnFocus) {
            returnFocus.focus({ preventScroll: true });
        }
    });

    document.addEventListener("keydown", (event) => {
        if (!dialog.open) {
            return;
        }

        if (event.key === "Escape") {
            event.preventDefault();
            closeLightbox();
            return;
        }

        if (event.key === "ArrowLeft") {
            event.preventDefault();
            updateImage(currentIndex - 1);
        }

        if (event.key === "ArrowRight") {
            event.preventDefault();
            updateImage(currentIndex + 1);
        }
    });
})();
