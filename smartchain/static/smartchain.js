function getTimeBasedGreeting(date) {
    const hour = date.getHours();
    if (hour >= 5 && hour < 12) return "Good morning";
    if (hour >= 12 && hour < 17) return "Good afternoon";
    return "Good evening";
}

function updateSmartChainClock() {
    const now = new Date();
    const greeting = document.querySelector("[data-greeting]");
    const dateLabel = document.querySelector("[data-live-date]");
    const timeLabel = document.querySelector("[data-live-time]");
    if (greeting) greeting.textContent = getTimeBasedGreeting(now);
    if (dateLabel) dateLabel.textContent = new Intl.DateTimeFormat(undefined, { weekday: "long", day: "numeric", month: "long", year: "numeric" }).format(now);
    if (timeLabel) timeLabel.textContent = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(now);
}

if (typeof document !== "undefined") {
    document.addEventListener("DOMContentLoaded", function () {
        updateSmartChainClock();
        if (document.querySelector("[data-live-time]")) window.setInterval(updateSmartChainClock, 1000);
    });
}

if (typeof module !== "undefined") module.exports = { getTimeBasedGreeting };
