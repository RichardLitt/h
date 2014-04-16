# Annotator plugin for fuzzy text matching
class Annotator.Plugin.FuzzyTextAnchors extends Annotator.Plugin

  pluginInit: ->

    @$ = Annotator.$

    # Initialize the text matcher library
    @textFinder = new DomTextMatcher()

    # Register our fuzzy strategies
    @annotator.registerAnchoringStrategy
      # Two-phased fuzzy text matching strategy. (Using context and quote.)
      # This can handle document structure changes,
      # and also content changes.
      name: "two-phase fuzzy"
      priority: 60
      create: @_createAnchorWithTwoPhaseFuzzyMatching
      verify: @_rejectFuzzyTextAnchor

    @annotator.registerAnchoringStrategy
      # Naive fuzzy text matching strategy. (Using only the quote.)
      # This can handle document structure changes,
      # and also content changes.
      name: "one-phase fuzzy"
      priority: 70
      create: @_createAnchorWithFuzzyMatching
      verify: @_rejectFuzzyTextAnchor

  # Verify a text position anchor
  _rejectFuzzyTextAnchor: (anchor, reason, data) =>
    # Prepare the deferred object
    dfd = @$.Deferred()

    if reason is "corpus change"
      # If we have a corpus change, then we have no idea whether this is
      # still the best match, so let's conclude that this anchor is no longer
      # valid
      dfd.resolve false

    else
      dfd.resolve true  # We don't care until the corpus has changed

    # Return the promise
    dfd.promise()

  _createAnchorWithTwoPhaseFuzzyMatching: (target) =>
    # Prepare the deferred object
    dfd = @$.Deferred()

    # Fetch the quote and the context
    quoteSelector = @annotator.findSelector target.selector, "TextQuoteSelector"
    unless quoteSelector
      dfd.reject "no TextQuoteSelector found", true
      return dfd.promise()

    prefix = quoteSelector.prefix
    suffix = quoteSelector.suffix
    quote = quoteSelector.exact

    # No context, to joy
    unless prefix and suffix
      dfd.reject "prefix and suffix is required"
      return dfd.promise()

    # Fetch the expected start and end positions
    posSelector = @annotator.findSelector target.selector, "TextPositionSelector"
    expectedStart = posSelector?.start
    expectedEnd = posSelector?.end

    @annotator.domMapper.prepare("anchoring").then (s) =>
      options =
        contextMatchDistance: s.getCorpus().length * 2
        contextMatchThreshold: 0.5
        patternMatchThreshold: 0.5
        flexContext: true
      result = @textFinder.searchFuzzyWithContext s.getCorpus(), prefix, suffix, quote,
        expectedStart, expectedEnd, false, options

      # If we did not got a result, give up
      unless result.matches.length
        dfd.reject "fuzzy match found no result for '" + quote + "' @ " + expectedStart + "."
        return dfd.promise()

      # here is our result
      match = result.matches[0]
#      console.log "2-phase fuzzy found match at: [" + match.start + ":" +
#        match.end + "]: '" + match.found + "' (exact: " + match.exact + ")"

      # OK, we have everything
      # Create a TextPositionAnchor from this data
      dfd.resolve
        type: "text position"
        start: match.start
        end: match.end
        startPage: s.getPageIndexForPos match.start
        endPage: s.getPageIndexForPos match.end
        quote: match.found
        diffHTML: unless match.exact then match.comparison.diffHTML
        diffCaseOnly: unless match.exact then match.exactExceptCase

    # Return the promise
    dfd.promise()

  _createAnchorWithFuzzyMatching: (target) =>
    # Prepare the deferred object
    dfd = @$.Deferred()

    # Fetch the quote
    quoteSelector = @annotator.findSelector target.selector, "TextQuoteSelector"
    unless quoteSelector
      dfd.reject "no TextQuoteSelector found", true
      return dfd.promise()

    quote = quoteSelector.exact

    # No quote, no joy
    unless quote
      dfd.reject "quote is required"
      return dfd.promise()

    # For too short quotes, this strategy is bound to return false positives.
    # See https://github.com/hypothesis/h/issues/853 for details.
    unless quote.length >= 32
      dfd.reject "can't use this strategy for quotes this short"
      return dfd.promise()

    # Get a starting position for the search
    posSelector = @annotator.findSelector target.selector, "TextPositionSelector"
    expectedStart = posSelector?.start

    # Get d-t-m into a ready state
    @annotator.domMapper.prepare("anchoring").then (s) =>

      # Get full document length
      len = s.getCorpus().length

      # If we don't have the position saved, start at the middle of the doc
      expectedStart ?= Math.floor(len / 2)

      # Do the fuzzy search
      options =
        matchDistance: len * 2
        withFuzzyComparison: true
      result = @textFinder.searchFuzzy s.getCorpus(), quote, expectedStart,
        false, options

      # If we did not got a result, give up
      unless result.matches.length
        dfd.reject "fuzzy found no match for '" + quote + "' @ " + expectedStart
        return dfd.promise()

      # here is our result
      match = result.matches[0]
#      console.log "1-phase fuzzy found match at: [" + match.start + ":" +
#        match.end + "]: '" + match.found + "' (exact: " + match.exact + ")"

      # OK, we have everything
      # Create a TextPositionAnchor from this data
      dfd.resolve
        type: "text position"
        start: match.start
        end: match.end
        startPage: s.getPageIndexForPos match.start
        endPage: s.getPageIndexForPos match.end
        quote: match.found
        diffHTML: unless match.exact then match.comparison.diffHTML
        diffCaseOnly: unless match.exact then match.exactExceptCase

    # Return the promise
    dfd.promise()
