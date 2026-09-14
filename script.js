/* ==========================================================================
   CRYPT//GEN
   Password Generator + Entropy + Brute-Force Estimator
   100% Client-Side
   ========================================================================== */


/* ==========================================================================
   CHARACTER SETS
   ========================================================================== */

const CHARSETS = {
    lowercase: "abcdefghijklmnopqrstuvwxyz",
    uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    numbers: "0123456789",
    symbols: "!@#$%^&*()-_=+[]{};:,.?/|~"
};


/* ==========================================================================
   CONFIGURATION
   ========================================================================== */

const CONFIG = {
    minLength: 4,
    maxLength: 50,

    /*
     * The attack model used by the UI.
     *
     * This is intentionally a clearly labeled theoretical estimate.
     * 1 trillion guesses/second = 1e12.
     */
    guessesPerSecond: 1e12,

    /*
     * Seconds used for time conversions.
     */
    secondsPerMinute: 60,
    secondsPerHour: 60 * 60,
    secondsPerDay: 60 * 60 * 24,
    secondsPerYear: 60 * 60 * 24 * 365.25
};


/* ==========================================================================
   DOM
   ========================================================================== */

const elements = {
    loader: document.getElementById("loader"),
    loaderStatus: document.getElementById("loaderStatus"),

    passwordOutput:
        document.getElementById("passwordOutput"),

    copyButton:
        document.getElementById("copyButton"),

    copyFeedback:
        document.getElementById("copyFeedback"),

    generateButton:
        document.getElementById("generateButton"),

    lengthRange:
        document.getElementById("lengthRange"),

    lengthValue:
        document.getElementById("lengthValue"),

    lowercase:
        document.getElementById("lowercase"),

    uppercase:
        document.getElementById("uppercase"),

    numbers:
        document.getElementById("numbers"),

    symbols:
        document.getElementById("symbols"),

    guaranteeTypes:
        document.getElementById("guaranteeTypes"),

    analysisState:
        document.getElementById("analysisState"),

    strengthLabel:
        document.getElementById("strengthLabel"),

    strengthMeter:
        document.getElementById("strengthMeter"),

    strengthDescription:
        document.getElementById("strengthDescription"),

    statLength:
        document.getElementById("statLength"),

    statPool:
        document.getElementById("statPool"),

    statEntropy:
        document.getElementById("statEntropy"),

    statCombinations:
        document.getElementById("statCombinations"),

    averageTime:
        document.getElementById("averageTime"),

    worstTime:
        document.getElementById("worstTime")
};


/* ==========================================================================
   STATE
   ========================================================================== */

const state = {
    password: "",
    length: 16,

    selectedTypes: {
        lowercase: true,
        uppercase: true,
        numbers: true,
        symbols: true
    },

    guaranteeTypes: true
};


/* ==========================================================================
   CRYPTOGRAPHIC RANDOM NUMBER
   ========================================================================== */

/**
 * Returns a cryptographically secure random integer.
 *
 * Uses rejection sampling instead of:
 *
 * Math.random()
 *
 * This prevents modulo bias.
 */
function secureRandomInt(max) {

    if (!Number.isInteger(max) || max <= 0) {
        throw new Error("Invalid random range.");
    }

    const maxUint32 = 0xFFFFFFFF;

    const limit =
        maxUint32 -
        ((maxUint32 + 1) % max);

    const randomBuffer =
        new Uint32Array(1);

    let randomValue;

    do {
        crypto.getRandomValues(randomBuffer);

        randomValue = randomBuffer[0];

    } while (randomValue >= limit);

    return randomValue % max;
}


/* ==========================================================================
   GET SELECTED CHARACTER SET
   ========================================================================== */

function getSelectedCharacterSets() {

    const selected = [];

    if (state.selectedTypes.lowercase) {
        selected.push({
            key: "lowercase",
            chars: CHARSETS.lowercase
        });
    }

    if (state.selectedTypes.uppercase) {
        selected.push({
            key: "uppercase",
            chars: CHARSETS.uppercase
        });
    }

    if (state.selectedTypes.numbers) {
        selected.push({
            key: "numbers",
            chars: CHARSETS.numbers
        });
    }

    if (state.selectedTypes.symbols) {
        selected.push({
            key: "symbols",
            chars: CHARSETS.symbols
        });
    }

    return selected;
}


/* ==========================================================================
   BUILD CHARACTER POOL
   ========================================================================== */

function buildCharacterPool(selectedSets) {

    return selectedSets
        .map(set => set.chars)
        .join("");
}


/* ==========================================================================
   SHUFFLE
   ========================================================================== */

/**
 * Fisher-Yates shuffle using crypto.getRandomValues().
 */
function secureShuffle(array) {

    for (
        let i = array.length - 1;
        i > 0;
        i--
    ) {

        const j = secureRandomInt(i + 1);

        [
            array[i],
            array[j]
        ] = [
            array[j],
            array[i]
        ];
    }

    return array;
}


/* ==========================================================================
   GENERATE PASSWORD
   ========================================================================== */

function generatePassword() {

    const selectedSets =
        getSelectedCharacterSets();

    if (selectedSets.length === 0) {

        showError(
            "SELECT AT LEAST ONE CHARACTER TYPE."
        );

        return;
    }

    const pool =
        buildCharacterPool(selectedSets);

    const passwordCharacters = [];


    /*
     * Guarantee one character from every
     * selected character category.
     */
    if (state.guaranteeTypes) {

        if (state.length < selectedSets.length) {

            state.length = selectedSets.length;

            elements.lengthRange.value =
                state.length;

            elements.lengthValue.textContent =
                state.length;
        }

        selectedSets.forEach(set => {

            const index =
                secureRandomInt(set.chars.length);

            passwordCharacters.push(
                set.chars[index]
            );
        });
    }


    /*
     * Fill the remaining password length
     * from the complete selected pool.
     */
    while (
        passwordCharacters.length <
        state.length
    ) {

        const index =
            secureRandomInt(pool.length);

        passwordCharacters.push(
            pool[index]
        );
    }


    /*
     * Shuffle so the guaranteed characters
     * are not always placed at the beginning.
     */
    secureShuffle(passwordCharacters);


    state.password =
        passwordCharacters.join("");

    elements.passwordOutput.textContent =
        state.password;


    /*
     * Update analysis immediately.
     */
    updateAnalysis();
}


/* ==========================================================================
   BIG NUMBER POWER
   ========================================================================== */

/**
 * Calculates base^exponent using logarithmic
 * representation for UI statistics.
 *
 * We don't actually need the enormous number itself.
 */
function calculateLog10Combinations(
    poolSize,
    length
) {

    return length * Math.log10(poolSize);
}


/* ==========================================================================
   FORMAT SCIENTIFIC NUMBER
   ========================================================================== */

function formatScientificFromLog10(log10Value) {

    if (!Number.isFinite(log10Value)) {
        return "0";
    }

    if (log10Value < 3) {

        return Math.round(
            Math.pow(10, log10Value)
        ).toLocaleString();
    }

    const exponent =
        Math.floor(log10Value);

    const mantissa =
        Math.pow(
            10,
            log10Value - exponent
        );

    return `${mantissa.toFixed(2)} × 10${toSuperscript(exponent)}`;
}


/* ==========================================================================
   SUPERSCRIPT
   ========================================================================== */

function toSuperscript(number) {

    const map = {
        "0": "⁰",
        "1": "¹",
        "2": "²",
        "3": "³",
        "4": "⁴",
        "5": "⁵",
        "6": "⁶",
        "7": "⁷",
        "8": "⁸",
        "9": "⁹",
        "-": "⁻"
    };

    return String(number)
        .split("")
        .map(character => map[character] || character)
        .join("");
}


/* ==========================================================================
   ENTROPY
   ========================================================================== */

function calculateEntropy(
    poolSize,
    length
) {

    if (
        poolSize <= 0 ||
        length <= 0
    ) {
        return 0;
    }

    return (
        length *
        Math.log2(poolSize)
    );
}


/* ==========================================================================
   BRUTE FORCE TIME
   ========================================================================== */

function calculateBruteForceTimes(
    log10Combinations
) {

    /*
     * combinations / guessesPerSecond
     *
     * We operate in log10 to avoid overflow.
     */

    const log10AverageSeconds =
        log10Combinations -
        Math.log10(CONFIG.guessesPerSecond);

    const log10WorstSeconds =
        log10Combinations -
        Math.log10(CONFIG.guessesPerSecond) +
        Math.log10(2);


    return {
        average:
            formatTimeFromLog10Seconds(
                log10AverageSeconds
            ),

        worst:
            formatTimeFromLog10Seconds(
                log10WorstSeconds
            )
    };
}


/* ==========================================================================
   FORMAT TIME
   ========================================================================== */

function formatTimeFromLog10Seconds(
    log10Seconds
) {

    if (!Number.isFinite(log10Seconds)) {
        return "INSTANT";
    }


    /*
     * Less than one second.
     */
    if (log10Seconds < 0) {

        const seconds =
            Math.pow(10, log10Seconds);

        if (seconds < 0.001) {
            return "< 1 MS";
        }

        if (seconds < 1) {
            return `${Math.round(seconds * 1000)} MS`;
        }

        return `${seconds.toFixed(2)} SEC`;
    }


    const log10Minute =
        Math.log10(
            CONFIG.secondsPerMinute
        );

    const log10Hour =
        Math.log10(
            CONFIG.secondsPerHour
        );

    const log10Day =
        Math.log10(
            CONFIG.secondsPerDay
        );

    const log10Year =
        Math.log10(
            CONFIG.secondsPerYear
        );


    if (log10Seconds < log10Minute) {

        const seconds =
            Math.pow(10, log10Seconds);

        return `${formatSmallTime(seconds)} SEC`;
    }


    if (log10Seconds < log10Hour) {

        const minutes =
            Math.pow(
                10,
                log10Seconds - log10Minute
            );

        return `${formatSmallTime(minutes)} MIN`;
    }


    if (log10Seconds < log10Day) {

        const hours =
            Math.pow(
                10,
                log10Seconds - log10Hour
            );

        return `${formatSmallTime(hours)} HOURS`;
    }


    if (log10Seconds < log10Year) {

        const days =
            Math.pow(
                10,
                log10Seconds - log10Day
            );

        return `${formatLargeTime(days)} DAYS`;
    }


    const years =
        log10Seconds - log10Year;


    /*
     * If years are beyond normal floating
     * point readability, show scientific form.
     */
    if (years > 15) {

        const exponent =
            Math.floor(years);

        const mantissa =
            Math.pow(
                10,
                years - exponent
            );

        return `${mantissa.toFixed(2)} × 10${toSuperscript(exponent)} YEARS`;
    }


    const numericYears =
        Math.pow(10, years);

    return `${formatLargeTime(numericYears)} YEARS`;
}


/* ==========================================================================
   TIME FORMATTING HELPERS
   ========================================================================== */

function formatSmallTime(value) {

    if (value < 10) {
        return value.toFixed(2);
    }

    if (value < 100) {
        return value.toFixed(1);
    }

    return Math.round(value).toLocaleString();
}


function formatLargeTime(value) {

    if (value < 10) {
        return value.toFixed(2);
    }

    if (value < 1000) {
        return Math.round(value).toLocaleString();
    }

    return value.toExponential(2);
}


/* ==========================================================================
   STRENGTH
   ========================================================================== */

function calculateStrength(
    entropy,
    length
) {

    let score = 0;

    if (entropy >= 30) score = 1;
    if (entropy >= 50) score = 2;
    if (entropy >= 70) score = 3;
    if (entropy >= 90) score = 4;
    if (entropy >= 110) score = 5;
    if (entropy >= 130) score = 6;


    /*
     * Very short passwords should never
     * appear as "extreme".
     */
    if (length <= 6) {
        score = Math.min(score, 1);
    }

    else if (length <= 8) {
        score = Math.min(score, 2);
    }

    else if (length <= 10) {
        score = Math.min(score, 3);
    }


    return score;
}


/* ==========================================================================
   UPDATE STRENGTH UI
   ========================================================================== */

function updateStrength(
    entropy,
    length
) {

    const score =
        calculateStrength(
            entropy,
            length
        );


    const strengthData = {

        0: {
            label: "VERY WEAK",
            width: "10%",
            description:
                "Extremely vulnerable to brute-force guessing."
        },

        1: {
            label: "WEAK",
            width: "25%",
            description:
                "This password should not be used for important accounts."
        },

        2: {
            label: "MODERATE",
            width: "42%",
            description:
                "Better, but longer passwords are recommended."
        },

        3: {
            label: "STRONG",
            width: "60%",
            description:
                "Strong against many practical guessing attacks."
        },

        4: {
            label: "VERY STRONG",
            width: "78%",
            description:
                "A highly resistant password when randomly generated."
        },

        5: {
            label: "EXTREME",
            width: "92%",
            description:
                "Extremely strong password."
        },

        6: {
            label: "EXTREME+",
            width: "100%",
            description:
                "Exceptionally large search space."
        }
    };


    const data =
        strengthData[score];


    elements.strengthLabel.textContent =
        data.label;

    elements.strengthMeter.style.width =
        data.width;

    elements.strengthDescription.textContent =
        data.description;
}


/* ==========================================================================
   UPDATE ANALYSIS
   ========================================================================== */

function updateAnalysis() {

    const selectedSets =
        getSelectedCharacterSets();

    if (selectedSets.length === 0) {

        elements.analysisState.textContent =
            "WAITING";

        return;
    }


    elements.analysisState.textContent =
        "CALCULATING";


    const pool =
        buildCharacterPool(selectedSets);

    const poolSize =
        pool.length;

    const length =
        state.length;


    const entropy =
        calculateEntropy(
            poolSize,
            length
        );

    const log10Combinations =
        calculateLog10Combinations(
            poolSize,
            length
        );


    const combinations =
        formatScientificFromLog10(
            log10Combinations
        );


    const bruteForce =
        calculateBruteForceTimes(
            log10Combinations
        );


    elements.statLength.textContent =
        length;

    elements.statPool.textContent =
        poolSize;

    elements.statEntropy.textContent =
        `${entropy.toFixed(1)} bits`;

    elements.statCombinations.textContent =
        combinations;

    elements.averageTime.textContent =
        bruteForce.average;

    elements.worstTime.textContent =
        bruteForce.worst;


    updateStrength(
        entropy,
        length
    );


    elements.analysisState.textContent =
        "LIVE";
}


/* ==========================================================================
   ERROR
   ========================================================================== */

function showError(message) {

    elements.copyFeedback.textContent =
        message;

    elements.copyFeedback.style.color =
        "#4dafff";

    window.setTimeout(() => {

        elements.copyFeedback.textContent =
            "";

    }, 2500);
}


/* ==========================================================================
   COPY
   ========================================================================== */

async function copyPassword() {

    if (!state.password) {
        return;
    }


    try {

        await navigator.clipboard.writeText(
            state.password
        );

        elements.copyFeedback.textContent =
            "PASSWORD COPIED TO CLIPBOARD";

    }

    catch {

        /*
         * Fallback for older browsers.
         */
        const textArea =
            document.createElement("textarea");

        textArea.value =
            state.password;

        textArea.style.position =
            "fixed";

        textArea.style.opacity =
            "0";

        document.body.appendChild(
            textArea
        );

        textArea.select();

        try {

            document.execCommand("copy");

            elements.copyFeedback.textContent =
                "PASSWORD COPIED TO CLIPBOARD";

        }

        catch {

            elements.copyFeedback.textContent =
                "COPY FAILED — COPY MANUALLY";

        }

        textArea.remove();
    }


    window.setTimeout(() => {

        elements.copyFeedback.textContent =
            "";

    }, 2500);
}


/* ==========================================================================
   SYNC STATE FROM UI
   ========================================================================== */

function syncState() {

    state.length =
        Number(
            elements.lengthRange.value
        );

    state.selectedTypes.lowercase =
        elements.lowercase.checked;

    state.selectedTypes.uppercase =
        elements.uppercase.checked;

    state.selectedTypes.numbers =
        elements.numbers.checked;

    state.selectedTypes.symbols =
        elements.symbols.checked;

    state.guaranteeTypes =
        elements.guaranteeTypes.checked;


    elements.lengthValue.textContent =
        state.length;
}


/* ==========================================================================
   LENGTH CHANGE
   ========================================================================== */

function handleLengthChange() {

    syncState();

    const selectedCount =
        getSelectedCharacterSets().length;


    /*
     * If "one from each type" is active,
     * don't allow a length smaller than
     * the number of selected categories.
     */
    if (
        state.guaranteeTypes &&
        selectedCount > state.length
    ) {

        state.length =
            selectedCount;

        elements.lengthRange.value =
            state.length;

        elements.lengthValue.textContent =
            state.length;
    }


    generatePassword();
}


/* ==========================================================================
   CHARACTER TYPE CHANGE
   ========================================================================== */

function handleCharacterChange() {

    syncState();

    const selectedSets =
        getSelectedCharacterSets();


    if (selectedSets.length === 0) {

        /*
         * Prevent the user from disabling
         * every character category.
         */
        const lastCheckbox =
            event?.target;

        if (lastCheckbox) {
            lastCheckbox.checked = true;
        }

        syncState();

        showError(
            "AT LEAST ONE CHARACTER TYPE IS REQUIRED."
        );

        return;
    }


    const selectedCount =
        selectedSets.length;


    if (
        state.guaranteeTypes &&
        state.length < selectedCount
    ) {

        state.length =
            selectedCount;

        elements.lengthRange.value =
            state.length;

        elements.lengthValue.textContent =
            state.length;
    }


    generatePassword();
}


/* ==========================================================================
   GUARANTEE CHANGE
   ========================================================================== */

function handleGuaranteeChange() {

    syncState();

    const selectedCount =
        getSelectedCharacterSets().length;


    if (
        state.guaranteeTypes &&
        state.length < selectedCount
    ) {

        state.length =
            selectedCount;

        elements.lengthRange.value =
            state.length;

        elements.lengthValue.textContent =
            state.length;
    }


    generatePassword();
}


/* ==========================================================================
   EVENTS
   ========================================================================== */

elements.generateButton.addEventListener(
    "click",
    generatePassword
);

elements.copyButton.addEventListener(
    "click",
    copyPassword
);

elements.lengthRange.addEventListener(
    "input",
    handleLengthChange
);

[
    elements.lowercase,
    elements.uppercase,
    elements.numbers,
    elements.symbols
].forEach(input => {

    input.addEventListener(
        "change",
        handleCharacterChange
    );
});


elements.guaranteeTypes.addEventListener(
    "change",
    handleGuaranteeChange
);


/* ==========================================================================
   INITIALIZATION
   ========================================================================== */

function initialize() {

    syncState();

    /*
     * Initial password.
     */
    generatePassword();


    /*
     * Small artificial initialization delay
     * so the loading screen feels intentional
     * rather than flashing for a few milliseconds.
     */
    window.setTimeout(() => {

        elements.loaderStatus.textContent =
            "SECURITY CORE ONLINE";

    }, 250);


    window.setTimeout(() => {

        elements.loader.classList.add(
            "loaded"
        );

    }, 650);
}


/* ==========================================================================
   START
   ========================================================================== */

if (
    document.readyState === "loading"
) {

    document.addEventListener(
        "DOMContentLoaded",
        initialize,
        {
            once: true
        }
    );

}

else {

    initialize();
}