function httpRequest(url, processResponse, payload) {
    FreezeUI();
    let method = (payload !== undefined) ? 'POST' : 'GET';
    fetch(url, { method: method, headers: {'Content-Type': 'application/json'}, body: (method === 'POST') ? JSON.stringify(payload) : null})
        .then(
            function(response) {
                if (response.status !== 200) {
                    UnFreezeUI();
                    displayError(`Looks like there was a problem. Status Code: ${response.status}`);
                    return;
                }
                response.json().then(function(data) {
                    UnFreezeUI();
                    if(Object.keys(data).includes("error")) {
                        return displayError(data.error);
                    }
                    processResponse(data);
                });
            }
        )
        .catch(function(err) {
            displayError(`Fetch error: ${err}`);
        });
}

function displayError(message) {
    let div_overlay = document.createElement("div");
    div_overlay.classList.add("error-overlay");
    let div_overlay_span = document.createElement("span");
    div_overlay_span.innerText = message;
    div_overlay.appendChild(div_overlay_span);
    document.body.appendChild(div_overlay);
    setTimeout(function() {
        div_overlay.style.transition = "opacity 0.5s ease";
        div_overlay.style.opacity = 0;
        setTimeout(function() {
            document.body.removeChild(div_overlay);
        }, 500);
    }, 1000);
}


function hexdump(buffer, blockSize) {
    blockSize = blockSize || 16;
    var lines = [];
    var hex = "0123456789ABCDEF";
    for (var b = 0; b < buffer.length; b += blockSize) {
        var block = buffer.slice(b, Math.min(b + blockSize, buffer.length));
        var addr = ("0000" + b.toString(16)).slice(-4);
        var codes = block.split('').map(function (ch) {
            var code = ch.charCodeAt(0);
            return " " + hex[(0xF0 & code) >> 4] + hex[0x0F & code];
        }).join("");
        codes += "   ".repeat(blockSize - block.length);
        var chars = block.replace(/[\x00-\x1F\x20]/g, '.');
        chars +=  " ".repeat(blockSize - block.length);
        lines.push(addr + " " + codes + "  " + chars);
    }
    return lines.join("\n");
}
function get_selected_path(element, text) {
    var element_text = element.innerHTML;
    var element_paths = element_text.split("/");
    var text_paths = text.split("/");
    var text_underline = element_paths.slice(0, text_paths.length).join("/");
    if(text_underline !== element_text) {
        text_underline += "/";
    }
    if(text_underline === "/") {
        element.innerHTML = `<span class='navigate' data-path='${text_underline}' data-filetype='directory'>${text_underline}</span>${element_text.slice(element_text.indexOf(text_underline) + 1, element_text.length)}`;
    }
    else {
        element.innerHTML = `<span class='navigate' data-path='${text_underline}' data-filetype='directory'>${text_underline}</span>${element_text.split(text_underline).slice(-1).pop()}`;
    }
    return text_underline;
}
function get_text_position(element, clientX) {
    var characters = element; // div with text
    var charactersText = characters.textContent;
    var prevPos = 0, currPos = 0 , finlPos = -1;
    var textToUnderline = '';
    characters.textContent = '';
    for (var i = 0; i < charactersText.length; i++) {
        var textNode = document.createTextNode(charactersText[i]);
        characters.appendChild(textNode);
        var range = document.createRange();
        range.selectNodeContents(textNode);
        var rects = range.getClientRects();
        prevPos = parseInt(currPos, 10);
        currPos = parseInt(rects[0].right, 10);
        if(clientX >= currPos) {
            textToUnderline = characters.textContent;
            // console.log(prevPos, clientX, currPos, characters.textContent);
            finlPos = currPos;
        }
    }
    get_selected_path(element, textToUnderline);
    return finlPos;
}
function path_navigator_tracker() {
    const element = document.querySelector(".path_nav");
    element.addEventListener("mousemove", event => {
        // console.log("Mouse in", event);
        get_text_position(element, event.clientX);
        // console.log(element.offsetLeft, event.clientX, element.offsetLeft + element.offsetWidth, JSON.stringify(get_text_position(element, event.clientX)));
    });
    element.addEventListener("mouseleave", event => {
        // console.log("mouseleave!");
        element.innerHTML = element.textContent;
    });
}

function init_nav_tracker() {
    const path_nav = document.querySelector(".path-nav");
    const paths = path_nav.innerText.split("/");

    let res = '';
    for(var i = 0; i < paths.length; i++) {
        let filename = `${paths[i]}`;
        let full_path = (i > 0) ? `${paths.slice(0, i).join("/")}/${filename}` : '/';
        res += `<span class="navigate" id="path-${i}" data-path="${full_path}" data-filetype="directory">${filename}/</span>`;
    }
    document.querySelector(".path-nav").innerHTML = res;

    path_nav.addEventListener("mousemove", event => {
        let hovered_element = document.elementFromPoint(event.clientX, event.clientY);
        let hovered_element_path_id = hovered_element.id.substr(5).valueOf(); // extract the path id
        // now hover all the previous ones
        for(let i = 0; i < document.querySelectorAll("span[id^=path]").length; i++) {
            document.getElementById(`path-${i}`).style.textDecoration = (i <= hovered_element_path_id) ? 'underline' : 'none';
        }
    });
    path_nav.addEventListener("mouseleave", event => {
        for(let i = 0; i < document.querySelectorAll("span[id^=path]").length; i++) {
            document.getElementById(`path-${i}`).style.textDecoration = 'none';
        }
    });
}