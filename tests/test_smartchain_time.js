const assert = require("node:assert/strict");
const { getTimeBasedGreeting } = require("../smartchain/static/smartchain.js");

const cases = [
    ["08:00", "Good morning"],
    ["11:59", "Good morning"],
    ["12:00", "Good afternoon"],
    ["16:59", "Good afternoon"],
    ["17:00", "Good evening"],
    ["21:30", "Good evening"],
    ["00:30", "Good evening"],
    ["04:59", "Good evening"],
    ["05:00", "Good morning"],
];

for (const [time, expected] of cases) {
    const [hour, minute] = time.split(":").map(Number);
    assert.equal(getTimeBasedGreeting(new Date(2026, 8, 23, hour, minute)), expected, time);
}

console.log("time-boundaries-ok", cases.length);
