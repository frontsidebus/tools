// ==UserScript==
// @name         fIMCnow
// @namespace    http://tampermonkey.net/
// @version      0.1
// @description  try to take over the world!
// @author       You
// @match        https://imc.armor.com/*
// @grant        none
// ==/UserScript==

function fIMC_reIssue() {
    var myMenu = document.querySelector(".toolbar-menu-item");
    if (myMenu) { myMenu.click(); myMenu.click(); }
}

setInterval(function () {fIMC_reIssue();}, 300000);
