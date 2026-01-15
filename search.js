(function() {
  let fuse;
  let searchData = [];

  // Load the search index
  fetch('/search.json')
    .then(response => response.json())
    .then(data => {
      searchData = data;

      const options = {
        keys: ['content'],  
        threshold: 0.2,  
        distance: 100,
        minMatchCharLength: 2,
        includeScore: true,
        includeMatches: true,
        ignoreLocation: true,  
        findAllMatches: true
      };

      fuse = new Fuse(searchData, options);
    })
    .catch(error => console.error('Error loading search index:', error));

  // Get DOM elements
  const searchInput = document.getElementById('search-input');
  const searchResults = document.getElementById('search-results');
  const contentSections = document.querySelector('.content-sections');

  function debounce(func, wait) {
    let timeout;
    return function(...args) {
      clearTimeout(timeout);
      timeout = setTimeout(() => func.apply(this, args), wait);
    };
  }

  // Highlight matching text using Fuse.js match indices
  function highlightTextWithMatches(text, matches) {
    if (!matches || matches.length === 0) return text;

    // Sort matches by start index in descending order to avoid offset issues
    const sortedMatches = [...matches].sort((a, b) => b[0] - a[0]);

    let result = text;
    for (const [start, end] of sortedMatches) {
      result = result.substring(0, start) +
               '<span class="highlight">' +
               result.substring(start, end + 1) +
               '</span>' +
               result.substring(end + 1);
    }

    return result;
  }

  // Get snippet around match using Fuse.js match indices
  function getSnippetWithMatches(content, matches, length = 200) {
    if (!content) return '';

    // If no matches, return beginning of content
    if (!matches || matches.length === 0) {
      return content.substring(0, length) + '...';
    }

    // Find the first match position
    const firstMatchStart = matches[0][0];

    const start = Math.max(0, firstMatchStart - length / 2);
    const end = Math.min(content.length, firstMatchStart + length / 2);

    let snippet = content.substring(start, end);
    if (start > 0) snippet = '...' + snippet;
    if (end < content.length) snippet = snippet + '...';

    // Adjust match indices relative to snippet
    const adjustedMatches = matches
      .filter(([matchStart, matchEnd]) => matchStart >= start && matchStart < end)
      .map(([matchStart, matchEnd]) => [
        matchStart - start + (start > 0 ? 3 : 0), // +3 for '...' prefix
        Math.min(matchEnd - start + (start > 0 ? 3 : 0), snippet.length - 1)
      ]);

    return highlightTextWithMatches(snippet, adjustedMatches);
  }

  // Get the actual matched text from the content for URL encoding
  function getFirstMatchedText(content, matches) {
    if (!matches || matches.length === 0) return '';
    const [start, end] = matches[0];
    return content.substring(start, end + 1);
  }

  // Perform search
  function performSearch(query) {
    if (!query || query.length < 2) {
      searchResults.style.display = 'none';
      searchResults.innerHTML = '';
      contentSections.classList.remove('hidden');
      return;
    }

    if (!fuse) {
      searchResults.innerHTML = '<p>Search index loading...</p>';
      searchResults.style.display = 'block';
      return;
    }

    const results = fuse.search(query);

    if (results.length === 0) {
      searchResults.innerHTML = '<p>No results found. Try different keywords.</p>';
      searchResults.style.display = 'block';
      contentSections.classList.add('hidden');
      return;
    }

    // Hide original content sections when showing results
    contentSections.classList.add('hidden');

    // Display results
    searchResults.innerHTML = results.slice(0, 10).map(result => {
      const item = result.item;

      const contentMatches = result.matches?.find(m => m.key === 'content');
      const titleMatches = result.matches?.find(m => m.key === 'title');
      const contentIndices = contentMatches?.indices || [];
      const titleIndices = titleMatches?.indices || [];

      const highlightedSnippet = getSnippetWithMatches(item.content || '', contentIndices);
      const highlightedTitle = highlightTextWithMatches(item.title, titleIndices);

      const matchedText = getFirstMatchedText(item.content || '', contentIndices);

      let url = item.path;
      if (matchedText && matchedText.length > 0) {
        // Encode the matched text for URL
        const encodedText = encodeURIComponent(matchedText.trim());
        url = `${item.path}#:~:text=${encodedText}`;
      }

      return `
        <a href="${url}" style="text-decoration: none; color: inherit;">
          <div class="search-result-item">
            <div class="search-result-title">${highlightedTitle}</div>
            <div class="search-result-snippet">${highlightedSnippet}</div>
          </div>
        </a>
      `;
    }).join('');

    searchResults.style.display = 'block';
  }

  searchInput.addEventListener('input', debounce(function(e) {
    performSearch(e.target.value);
  }, 300));

  searchInput.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
      searchInput.value = '';
      searchResults.style.display = 'none';
      searchResults.innerHTML = '';
      contentSections.classList.remove('hidden');
    }
  });
})();
