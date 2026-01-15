(function() {
  let fuse;
  let searchData = [];

  // Load the search index
  fetch('/search.json')
    .then(response => response.json())
    .then(data => {
      searchData = data;

      // Debug: log the first item to see the structure
      console.log('Search data sample:', data[0]);

      // Configure Fuse.js for fuzzy searching
      const options = {
        keys: ['content'],  // Only search content, not titles
        threshold: 0.2,     // Strict matching
        distance: 100,
        minMatchCharLength: 2,
        includeScore: true,
        includeMatches: true,
        ignoreLocation: true,  // Search anywhere in the document
        findAllMatches: true
      };

      fuse = new Fuse(searchData, options);
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

  // Highlight matching text
  function highlightText(text, query) {
    if (!query) return text;
    const regex = new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
    return text.replace(regex, '<span class="highlight">$1</span>');
  }

  // Get snippet around match
  function getSnippet(content, query, length = 200) {
    if (!content) return '';

    const lowerContent = content.toLowerCase();
    const lowerQuery = query.toLowerCase();
    const index = lowerContent.indexOf(lowerQuery);

    if (index === -1) {
      return content.substring(0, length) + '...';
    }

    const start = Math.max(0, index - length / 2);
    const end = Math.min(content.length, index + query.length + length / 2);

    let snippet = content.substring(start, end);
    if (start > 0) snippet = '...' + snippet;
    if (end < content.length) snippet = snippet + '...';

    return snippet;
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
      const snippet = getSnippet(item.content || '', query);
      const highlightedSnippet = highlightText(snippet, query);
      const highlightedTitle = highlightText(item.title, query);

      // Add text fragment for direct navigation to matched text
      const encodedQuery = encodeURIComponent(query.trim());
      const url = `${item.path}#:~:text=${encodedQuery}`;

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

  // Add event listener with debouncing
  searchInput.addEventListener('input', debounce(function(e) {
    performSearch(e.target.value);
  }, 300));

  // Clear search on Escape key
  searchInput.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
      searchInput.value = '';
      searchResults.style.display = 'none';
      searchResults.innerHTML = '';
      contentSections.classList.remove('hidden');
    }
  });
})();
