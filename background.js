// consider moving to user facing options
const resuse_th_tab = true;

// Set up context menu at install time.
chrome.runtime.onInstalled.addListener(function () {
    chrome.contextMenus.create({
        "contexts": ['selection'],
        "title": "!Search in Threat Hunting",
        "id": "search_th"
    });
});

function isIpAddress(ioc) {
    const ipAddressRegEx = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

    return ipAddressRegEx.test(ioc) ? true : false;
}

function isMd5Hash(ioc) {
    const md5RegEx = /\b[A-Fa-f0-9]{32}\b/;

    return md5RegEx.test(ioc) ? true : false;
}

// build TH query URL
function b64EncodeUnicode(str) {
    return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, function (match, p1) {
        return String.fromCharCode('0x' + p1);
    }));
}

function buildThUrl(q) {
    // last week
    const oneWeekInMs = 1000 * 60 * 60 * 24 * 7;
    q.from = ((new Date(Date.now() - oneWeekInMs)).toISOString());
    q.to = (new Date).toISOString();

    let encodedQ = b64EncodeUnicode(JSON.stringify(q))
    let qUrl = `https://portal.checkpoint.com/dashboard/endpoint/threathunting#/search/results?query=${encodedQ}`;
    return qUrl
}

function openNewTabWithUrl(url) {

    // reuse TH tab
    if (resuse_th_tab) {
        // look for already open TH
        chrome.tabs.query(
            { url: "https://portal.checkpoint.com/dashboard/endpoint/threathunting*", currentWindow: true },
            (tabs) => {
                if (tabs.length) {
                    console.log("TH tabs found", tabs);
                    chrome.tabs.update(tabs[0].id, { active: true, url: url });                    
                } else {
                    console.log('no TH tab found');

                    chrome.tabs.create({ url: url }, function (tab) {
                        tabId = tab.id;
                    });
                }
            }
        );

    } else {
        // no reuse - always open new tab
        chrome.tabs.create({ url: url }, function (tab) {
            tabId = tab.id;
        });
    }
}

// ioc is text from right-click context menu on selection
function searchThreatHuntingFor(ioc) {
    console.log('searchThreatHuntingFor', ioc);
    isIpAddress(ioc) && console.log('\tIP address:', ioc);
    isMd5Hash(ioc) && console.log('\tMD5 hash:', ioc);

    if (isIpAddress(ioc)) {
        const ipAddressThQueryTemplate = {
            "from": "2021-12-02T14:40:44.582Z",
            "to": "2021-12-09T14:40:44.582Z",
            "indicators": [
                {
                    "fieldArr": [
                        ioc
                    ],
                    "fieldType": "NetworkDestIP",
                    "operator": "Is"
                }
            ],
            "recordType": "Network",
            "timespanType": "custom"
        }

        openNewTabWithUrl(buildThUrl(ipAddressThQueryTemplate));
    } else if (isMd5Hash(ioc)) {
        const md5ThQueryTemplate = {
            "from": "2021-12-02T14:40:44.582Z",
            "to": "2021-12-09T14:40:44.582Z",
            "indicators": [
                {
                    "fieldArr": [
                        ioc
                    ],
                    "fieldType": "FileMD5",
                    "operator": "Is"
                }
            ],
            "recordType": "File",
            "timespanType": "custom"
        }
        openNewTabWithUrl(buildThUrl(md5ThQueryTemplate));
    } else {
        // everything else is considered domain
        let domainThQueryTemplate = {
            "from": "2021-12-02T14:40:44.582Z",
            "to": "2021-12-09T14:40:44.582Z",
            "indicators": [
                {
                    "fieldArr": [
                        ioc
                    ],
                    "fieldType": "NetworkDomain",
                    "operator": "Is"
                }
            ],
            "recordType": "Network",
            "timespanType": "custom"
        }
        openNewTabWithUrl(buildThUrl(domainThQueryTemplate));
    }
}

function onContextMenuClicked(info) {
    console.log(JSON.stringify(info));

    // handle context menu
    const { menuItemId, selectionText } = info;

    // search for selected text (IoC)
    if (menuItemId === 'search_th') {
        if (typeof selectionText === 'string') {
            searchThreatHuntingFor(selectionText.trim());
        }

    }
}

chrome.contextMenus.onClicked.addListener(onContextMenuClicked);