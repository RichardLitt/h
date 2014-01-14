# Annotator plugin for fuzzy text matching
class Annotator.Plugin.FuzzyTextAnchors extends Annotator.Plugin

  pluginInit: ->

    @Annotator = Annotator
    @$ = Annotator.$

    # Do we have the basic text anchors plugin loaded?
    unless @annotator.plugins.TextAnchors
      throw "The FuzzyTextAnchors Annotator plugin requires the TextAnchors plugin."
    # Initialize the text matcher library
    @textFinder = new DomTextMatcher => @annotator.anchoring.domMapper.getCorpus()

    # Register our fuzzy strategies
    @annotator.anchoring.anchoringStrategies.push
      # Two-phased fuzzy text matching strategy. (Using context and quote.)
      # This can handle document structure changes,
      # and also content changes.
      name: "two-phase fuzzy"
      create: @twoPhaseFuzzyMatching
      verify: @verifyFuzzyTextAnchor

    @annotator.anchoring.anchoringStrategies.push
      # Naive fuzzy text matching strategy. (Using only the quote.)
      # This can handle document structure changes,
      # and also content changes.
      name: "one-phase fuzzy"
      create: @fuzzyMatching
      verify: @verifyFuzzyTextAnchor

  # Verify a text position anchor
  verifyFuzzyTextAnchor: (anchor, reason, data) =>
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

  twoPhaseFuzzyMatching: (annotation, target) =>
    # Prepare the deferred object
    dfd = @$.Deferred()

    # We need the corpus from the document.
    unless @annotator.anchoring.domMapper.getCorpus
      dfd.reject "can't get corpus of document"
      return dfd.promise()

    # Fetch the quote and the context
    quoteSelector = @annotator.findSelector target.selector, "TextQuoteSelector"
    unless quoteSelector
      dfd.reject "no TextQuoteSelector found"
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

    options =
      contextMatchDistance: @annotator.anchoring.domMapper.getCorpus().length * 2
      contextMatchThreshold: 0.5
      patternMatchThreshold: 0.5
      flexContext: true
    result = @textFinder.searchFuzzyWithContext prefix, suffix, quote,
      expectedStart, expectedEnd, false, options

    # If we did not got a result, give up
    unless result.matches.length
      dfd.reject "fuzzy match found no result for '" + quote + "' @ " + expectedStart + "."
      return dfd.promise()

    # here is our result
    match = result.matches[0]
#    console.log "2-phase fuzzy found match at: [" + match.start + ":" +
#      match.end + "]: '" + match.found + "' (exact: " + match.exact + ")"

    # OK, we have everything
    # Create a TextPositionAnchor from this data
    dfd.resolve new @Annotator.TextPositionAnchor @annotator, annotation, target,
      match.start, match.end,
      (@annotator.anchoring.domMapper.getPageIndexForPos match.start),
      (@annotator.anchoring.domMapper.getPageIndexForPos match.end),
      match.found,
      unless match.exact then match.comparison.diffHTML,
      unless match.exact then match.exactExceptCase

    dfd.promise()

  fuzzyMatching: (annotation, target) =>
    # Prepare the deferred object
    dfd = @$.Deferred()

    # We need the corpus from the document.
    unless @annotator.anchoring.domMapper.getCorpus
      dfd.reject "can't get corpus of the document"
      return dfd.promise()

    # Fetch the quote
    quoteSelector = @annotator.findSelector target.selector, "TextQuoteSelector"
    unless quoteSelector
      dfd.reject "no TextQuoteSelector found"
      return dfd.promise()

    quote = quoteSelector.exact

    # No quote, no joy
    unless quote
      dfd.reject "quote is requored"
      return dfd.promise()

    # For too short quotes, this strategy is bound to return false positives.
    # See https://github.com/hypothesis/h/issues/853 for details.
    unless quote.length >= 32
      dfd.reject "can't use this strategy for quotes this short"
      return dfd.promise()

    # Get a starting position for the search
    posSelector = @annotator.findSelector target.selector, "TextPositionSelector"
    expectedStart = posSelector?.start

    # Get full document length
    len = @annotator.anchoring.domMapper.getCorpus().length

    # If we don't have the position saved, start at the middle of the doc
    expectedStart ?= Math.floor(len / 2)

    # Do the fuzzy search
    options =
      matchDistance: len * 2
      withFuzzyComparison: true
    result = @textFinder.searchFuzzy quote, expectedStart, false, options

    # If we did not got a result, give up
    unless result.matches.length
      dfd.reject "fuzzy found no match for '" + quote + "' @ " + expectedStart
      return dfd.promise()

    # here is our result
    match = result.matches[0]
#    console.log "1-phase fuzzy found match at: [" + match.start + ":" +
#      match.end + "]: '" + match.found + "' (exact: " + match.exact + ")"

    # OK, we have everything
    # Create a TextPosutionAnchor from this data
    dfd.resolve new @Annotator.TextPositionAnchor @annotator, annotation,
      target,
      match.start, match.end,
      (@annotator.anchoring.domMapper.getPageIndexForPos match.start),
      (@annotator.anchoring.domMapper.getPageIndexForPos match.end),
      match.found,
      unless match.exact then match.comparison.diffHTML,
      unless match.exact then match.exactExceptCase

    dfd.promise()
