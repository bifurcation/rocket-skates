'use strict';

const Promise   = require('bluebird');
const rp        = require('request-promise');
const fs        = Promise.promisifyAll(require('fs'));
const recursive = Promise.promisify(require('recursive-readdir'));

const SPEC_MD       = 'https://raw.githubusercontent.com/ietf-wg-acme/acme/master/draft-ietf-acme-acme.md';
const SPEC_HTML     = 'https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md';
const NORMATIVE_RE  = /MUST|SHOULD|MAY|REQUIRED/;
const CODE_BASE     = 'https://github.com/bifurcation/rocket-skates/tree/master/';
const CONCORD_RE    = /{{[a-z0-9-]+}}/;
const COVERAGE_FILE = 'SPEC_COVERAGE.md';
const TITLE         = '# Coverage of the ACME Specification\n';
const INTRO = `
This file is a summary of how well
[rocket-skates](https://github.com/bifurcation/rocket-skates) covers the
behaviors specified in the [ACME
specification](https://ietf-wg-acme.github.io/acme).  For each section of the
spec, we indicate where the behaviors in that section are implemented.  Sections
with no normative requirements are omitted.

`;

// Returns [[tag, index, text]]
function getSpecTags(url) {
  return rp.get(url)
    .then(spec => {
      let headers = [];
      let sections = {};
      let currHeader;
      let currText = '';
      spec.split('\n')
        .map(line => {
          if (line.match(/^#/)) {
            if (currHeader) {
              headers.push(currHeader);
              sections[currHeader] = currText;
            }

            currHeader = line;
            currText = '';
          } else {
            currText += line + '\n';
          }
        })


      let tagInfo = [];
      let lastLevel = 0;
      let counters = [0, 0, 0, 0, 0];
      for (let heading of headers) {
        let level = heading.replace(/[^#].*$/, '').length;
        if (level < lastLevel) {
          for (let i = level; i < counters.length; i += 1) {
            counters[i] = 0;
          }
        }
        lastLevel = level;

        let text = heading.substr(level)
                            .replace(/^[# ]*/, '')
                            .replace(/[# ]*$/, '');
        let tag = text.replace(/[^a-zA-Z0-9 -]/g, '')
                      .toLowerCase().replace(/ /g, '-');
        counters[level-1] += 1;

        // Only collect coverage data for sections that have RFC2119 keywords.
        // This means we have to manually exclude the terminology section, which
        // lists the keywords, but is not normative.
        if (sections[heading].match(NORMATIVE_RE) && (tag !== 'terminology')) {
          let index = counters.filter(x => x > 0).join('.');
          tagInfo.push({
            tag: tag,
            index: index,
            text: text
          });
        }
      }

      return tagInfo;
    });
}

// Returns [tag, fileName, lineNo]
function findTagsInJS(dir) {
  let fileNames;
  return recursive(__dirname + dir)
    .then(files => {
      fileNames = files.map(x => x.replace(/^.*rocket-skates\/lib/, 'lib'));
      let reads = files.map(file => fs.readFileAsync(file, 'utf8'));
      return Promise.all(reads);
    })
    .then(reads => {
      let concords = [];
      reads.map((content, i) => {
        content.split('\n')
          .map((line, lineNo) => {
            let match = line.match(CONCORD_RE);
            if (match) {
              let tag = match[0].replace(/[{}]/g, '');
              let file = fileNames[i].replace(/^.*\//, '');
              concords.push({
                tag: tag,
                file: file,
                path: fileNames[i],
                line: lineNo
              });
            }
          });
      });

      return concords;
    });
}

function joinTagTables(spec, client, server) {
  let data = [];
  for (let heading of spec) {
    data.push({
      tag:    heading.tag,
      spec:   heading,
      client: client.filter(code => code.tag === heading.tag),
      server: server.filter(code => code.tag === heading.tag)
    });
  }
  return data;
}

function renderTable(data) {
  let tagCount = data.length;
  let clientCount = data.filter(row => row.client.length > 0).length;
  let serverCount = data.filter(row => row.server.length > 0).length;
  let clientPct = (clientCount / tagCount * 100).toFixed(2);
  let serverPct = (serverCount / tagCount * 100).toFixed(2);
  let coverageRow = `| Coverage `
                  + `| ${clientCount} / ${tagCount} (${clientPct}%) `
                  + `| ${clientCount} / ${tagCount} (${clientPct}%) |`;

  let rows = [
    '| Spec | Client | Server |',
    '|:-----|:-------|:-------|',
    coverageRow,
    '|:-----|:-------|:-------|',
  ];

  for (let row of data) {
    // Form spec link
    let specText = `${row.spec.index} ${row.spec.text}`;
    let specURL = `${SPEC_HTML}#${row.tag}`;
    let specLink = `[${specText}](${specURL})`;

    // Form code links for client references
    let clientLinks = [];
    for (let match of row.client) {
      let text = `${match.file}:${match.line}`;
      let url = `${CODE_BASE}${match.path}#L${match.line}`;
      clientLinks.push(`[${text}](${url})`);
    }
    let clientLink = clientLinks.join(', ');
    if (!clientLink) {
      clientLink = '---';
    }

    // Form code links for server references
    let serverLinks = [];
    for (let match of row.server) {
      let text = `${match.file}:${match.line}`;
      let url = `${CODE_BASE}${match.path}#L${match.line}`;
      serverLinks.push(`[${text}](${url})`);
    }
    let serverLink = serverLinks.join(', ');
    if (!serverLink) {
      serverLink = '---';
    }

    rows.push(`| ${specLink} | ${clientLink} | ${serverLink} |`);
  }

  return rows;
}

let specTags;
let clientTags;
let serverTags;
getSpecTags(SPEC_MD)
  .then(tags => {
    specTags = tags;
    return findTagsInJS('/lib/client/');
  })
  .then(tags => {
    clientTags = tags;
    return findTagsInJS('/lib/server/');
  })
  .then(tags => {
    serverTags = tags;

    let tableData = joinTagTables(specTags, clientTags, serverTags);
    let tableLines = renderTable(tableData);

    let stream = fs.createWriteStream(COVERAGE_FILE);
    stream.once('open', () => {
      stream.write(TITLE);
      stream.write(INTRO);
      stream.write(tableLines.join('\n'));
    });
  })
