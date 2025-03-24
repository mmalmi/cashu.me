// src/stores/welcome.ts
import { defineStore } from "pinia";
import { useLocalStorage } from "@vueuse/core";
import { computed } from "vue";

export type WelcomeState = {
  showWelcome: boolean;
  currentSlide: number;
  seedPhraseValidated: boolean;
  termsAccepted: boolean;
};

// Define the Pinia store
export const useWelcomeStore = defineStore("welcome", {
  state: (): WelcomeState => ({
    showWelcome: useLocalStorage<boolean>("cashu.welcome.showWelcome", false),
    currentSlide: useLocalStorage<number>("cashu.welcome.currentSlide", 0),
    seedPhraseValidated: useLocalStorage<boolean>(
      "cashu.welcome.seedPhraseValidated",
      true
    ),
    termsAccepted: useLocalStorage<boolean>(
      "cashu.welcome.termsAccepted",
      true
    ),
  }),
  getters: {
    // Determines if the current slide is the last one
    isLastSlide: (state) => state.currentSlide === 3, // Adjust if you have more slides

    // Determines if the user can proceed to the next slide
    canProceed: (state) => {
      switch (state.currentSlide) {
        case 0:
          return true;
        case 1:
          return true; // Assuming no validation for PWA install
        case 2:
          return state.seedPhraseValidated;
        case 3:
          return state.termsAccepted;
        default:
          return false;
      }
    },

    // Determines if the user can navigate to the previous slide
    canGoPrev: (state) => state.currentSlide > 0,
  },
  actions: {
    /**
     * Initializes the welcome dialog based on local storage.
     * Should be called when the store is initialized.
     */
    initializeWelcome() {
      if (!this.showWelcome) {
        window.location.href = "/";
      }
    },

    /**
     * Closes the welcome dialog and marks it as seen.
     */
    closeWelcome() {
      this.showWelcome = false;
      // Redirect to home or desired route
      window.location.href =
        "/" + window.location.search + window.location.hash;
    },

    /**
     * Sets the current slide index.
     * @param index - The index of the slide to navigate to.
     */
    setCurrentSlide(index: number) {
      this.currentSlide = index;
    },

    /**
     * Marks the terms as accepted.
     */
    acceptTerms() {
      this.termsAccepted = true;
    },

    /**
     * Validates the seed phrase.
     */
    validateSeedPhrase() {
      this.seedPhraseValidated = true;
    },

    /**
     * Resets the welcome dialog state (useful for testing or resetting).
     */
    resetWelcome() {
      this.showWelcome = true;
      this.currentSlide = 0;
      this.termsAccepted = false;
      this.seedPhraseValidated = false;
    },

    /**
     * Navigates to the previous slide if possible.
     */
    goToPrevSlide() {
      if (this.canGoPrev) {
        this.currentSlide -= 1;
      }
      // Optionally, handle edge cases or emit events
    },

    /**
     * Navigates to the next slide if possible.
     * If on the last slide, it can close the welcome dialog.
     */
    goToNextSlide() {
      if (this.canProceed) {
        if (this.isLastSlide) {
          this.closeWelcome();
        } else {
          this.currentSlide += 1;
        }
      }
      // Optionally, handle edge cases or emit events
      console.log(`href: ${window.location.href}`);
    },
  },
});
