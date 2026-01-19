(function() {
  let uf;
  let searchData = [];
  let haystack = [];  // Array of content strings for uFuzzy

  // Load the search index
  fetch('/search.json')
    .then(response => response.json())
    .then(data => {
      searchData = data;
      haystack = data.map(item => item.content || '');

      // Configure uFuzzy
      uf = new uFuzzy({
        intraMode: 1,  // Allow single-error fuzzy matching (substitution, transposition, insertion, deletion)
        intraIns: 1,   // Allow 1 extra char between each char within a term
        intraChars: "[a-z\\d'_\\-.: ]",  // Allow special chars and spaces between matched chars
        interSplit: "[^A-Za-z\\d'_\\-.:]+",  // Don't split on underscores, hyphens, dots, colons
      });
    })
    .catch(error => console.error('Error loading search index:', error));

  // Get DOM elements
  const searchInput = document.getElementById('search-input');
  const searchResults = document.getElementById('search-results');
  const contentSections = document.querySelector('.content-sections');

  // Debounce function to avoid too many searches
  function debounce(func, wait) {
    let timeout;
    return function(...args) {
      clearTimeout(timeout);
      timeout = setTimeout(() => func.apply(this, args), wait);
    };
  }

  // Expand match to full word boundaries
  function expandToWord(content, start, end) {
    // Expand start backwards to word boundary
    while (start > 0 && /\w/.test(content[start - 1])) {
      start--;
    }
    // Expand end forwards to word boundary
    while (end < content.length && /\w/.test(content[end])) {
      end++;
    }
    return { start, end };
  }

  // Perform search
  function performSearch(query) {
    if (!query || query.length < 2) {
      searchResults.style.display = 'none';
      searchResults.innerHTML = '';
      contentSections.classList.remove('hidden');
      return;
    }

    if (!uf) {
      searchResults.innerHTML = '<p>Search index loading...</p>';
      searchResults.style.display = 'block';
      return;
    }

    // uFuzzy search
    // Escape " -" to prevent it being treated as exclusion syntax
    // (uFuzzy treats " -term" as "exclude results with term")
    let escapedQuery = query.startsWith('-') ? ' ' + query : query;
    escapedQuery = escapedQuery.replace(/ -/g, ' \\-');
    let [idxs, info, order] = uf.search(haystack, escapedQuery);

    // Fallback: if no results and query is long enough, try without first character
    // (uFuzzy can't handle first-character substitution errors)
    if ((!idxs || idxs.length === 0) && escapedQuery.length >= 3) {
      const fallbackQuery = escapedQuery.substring(1);
      [idxs, info, order] = uf.search(haystack, fallbackQuery);
    }


    if (!idxs || idxs.length === 0) {
      searchResults.innerHTML = '<p>No results found. Try different keywords.</p>';
      searchResults.style.display = 'block';
      contentSections.classList.add('hidden');
      return;
    }

    // Hide original content sections when showing results
    contentSections.classList.add('hidden');

    // Display results (use order if available, otherwise idxs)
    const resultsToShow = order ? order.slice(0, 10) : idxs.slice(0, 10);

    searchResults.innerHTML = resultsToShow.map((idx) => {
      // If we have order, idx is an info index; otherwise it's a doc index
      const docIdx = order ? info.idx[idx] : idx;
      const item = searchData[docIdx];
      const content = item.content || '';
      const ranges = order ? info.ranges[idx] : null;

      // Get snippet around the match
      let snippet = '';
      let matchedText = '';
      if (ranges && ranges.length > 0) {
        // ranges is flat array of character positions
        const firstStart = ranges[0];
        const lastEnd = ranges[ranges.length - 1];

        // Expand to full word boundaries for text fragment navigation
        const expanded = expandToWord(content, firstStart, lastEnd);
        matchedText = content.substring(expanded.start, expanded.end);

        // Create snippet centered on match
        const snippetStart = Math.max(0, firstStart - 100);
        const snippetEnd = Math.min(content.length, lastEnd + 100);
        snippet = content.substring(snippetStart, snippetEnd);

        // Highlight using uFuzzy's highlight function
        const adjustedRanges = ranges.map(r => r - snippetStart);
        snippet = uFuzzy.highlight(snippet, adjustedRanges, (part, matched) =>
          matched ? `<span class="highlight">${part}</span>` : part
        );

        if (snippetStart > 0) snippet = '...' + snippet;
        if (snippetEnd < content.length) snippet = snippet + '...';
      } else {
        snippet = content.substring(0, 200) + '...';
      }

      // Use matched text for navigation
      const encodedMatch = matchedText ? encodeURIComponent(matchedText) : encodeURIComponent(query.trim());
      const url = `${item.path}#:~:text=${encodedMatch}`;

      return `
        <a href="${url}" style="text-decoration: none; color: inherit;">
          <div class="search-result-item">
            <div class="search-result-title">${item.title}</div>
            <div class="search-result-snippet">${snippet}</div>
          </div>
        </a>
      `;
    }).join('');

    searchResults.style.display = 'block';
  }

  // Add event listener with debouncing
  searchInput.addEventListener('input', debounce(function(e) {
    performSearch(e.target.value);
  }, 300));

  // Handle keyboard shortcuts
  searchInput.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
      searchInput.value = '';
      searchResults.style.display = 'none';
      searchResults.innerHTML = '';
      contentSections.classList.remove('hidden');
    } else if (e.key === 'Enter') {
      // Re-run search (useful after back button)
      performSearch(searchInput.value);
    }
  });
})();
