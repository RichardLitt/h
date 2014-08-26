imports = [
  'h.filters',
  'h.searchfilters'
]


class Hypothesis extends Annotator
  events: {}

  # Plugin configuration
  options:
    noDocAccess: true
    Discovery: {}
    Permissions:
      userAuthorize: (action, annotation, user) ->
        if annotation.permissions
          tokens = annotation.permissions[action] || []

          if tokens.length == 0
            # Empty or missing tokens array: only admin can perform action.
            return false

          for token in tokens
            if this.userId(user) == token
              return true
            if token == 'group:__world__'
              return true
            if token == 'group:__authenticated__' and this.user?
              return true

          # No tokens matched: action should not be performed.
          return false

        # Coarse-grained authorization
        else if annotation.user
          return user and this.userId(user) == this.userId(annotation.user)

        # No authorization info on annotation: free-for-all!
        true
      showEditPermissionsCheckbox: false,
      showViewPermissionsCheckbox: false,
    Threading: {}

  # Internal state
  providers: null
  host: null

  tool: 'comment'
  visibleHighlights: false

  # Here as a noop just to make the Permissions plugin happy
  # XXX: Change me when Annotator stops assuming things about viewers
  viewer:
    addField: (-> )

  this.$inject = [
    '$document', '$location', '$rootScope', '$route', '$window',
  ]
  constructor: (
     $document,   $location,   $rootScope,   $route,   $window,
  ) ->
    super ($document.find 'body')

    window.annotator = this

    @providers = []
    @socialView =
      name: "none" # "single-player"

    this.patch_store()

    # Load plugins
    for own name, opts of @options
      if not @plugins[name] and name of Annotator.Plugin
        this.addPlugin(name, opts)

    # Set up the bridge plugin, which bridges the main annotation methods
    # between the host page and the panel widget.
    whitelist = [
      'diffHTML', 'inject', 'quote', 'ranges', 'target', 'id', 'references',
      'uri', 'diffCaseOnly', 'document',
    ]
    this.addPlugin 'Bridge',
      gateway: true
      formatter: (annotation) =>
        formatted = {}
        for k, v of annotation when k in whitelist
          formatted[k] = v
        if annotation.thread? and annotation.thread?.children.length
          formatted.reply_count = annotation.thread.flattenChildren().length
        else
          formatted.reply_count = 0
        formatted
      parser: (annotation) =>
        parsed = {}
        for k, v of annotation when k in whitelist
          parsed[k] = v
        parsed
      onConnect: (source, origin, scope) =>
        options =
          window: source
          origin: origin
          scope: "#{scope}:provider"
          onReady: =>
            console.log "Provider functions are ready for #{origin}"
            if source is $window.parent then @host = channel
        entities = []
        channel = this._setupXDM options

        channel.call
          method: 'getDocumentInfo'
          success: (info) =>
            entityUris = {}
            entityUris[info.uri] = true
            for link in info.metadata.link
              entityUris[link.href] = true if link.href
            for href of entityUris
              entities.push href
            this.plugins.Store?.loadAnnotations()

        channel.notify
          method: 'setTool'
          params: this.tool

        channel.notify
          method: 'setVisibleHighlights'
          params: this.visibleHighlights

        @providers.push
          channel: channel
          entities: entities

    # Add some info to new annotations
    this.subscribe 'beforeAnnotationCreated', (annotation) =>
      # Annotator assumes a valid array of targets and highlights.
      unless annotation.target?
        annotation.target = []
      unless annotation.highlights?
        annotation.highlights = []

      # Register it with the draft service, except when it's an injection
       # This is an injection. Delete the marker.
      if annotation.inject
        # Set permissions for private
        permissions = @plugins.Permissions
        userId = permissions.options.userId permissions.user
        annotation.permissions =
          read: [userId]
          admin: [userId]
          update: [userId]
          delete: [userId]

    # Set default owner permissions on all annotations
    for event in ['beforeAnnotationCreated', 'beforeAnnotationUpdated']
      this.subscribe event, (annotation) =>
        permissions = @plugins.Permissions
        if permissions.user?
          userId = permissions.options.userId(permissions.user)
          for action, roles of annotation.permissions
            unless userId in roles then roles.push userId

    # Remove annotations from the view when they are deleted
    this.subscribe 'annotationDeleted', (a) =>
      scope = @element.scope()
      scope.annotations = scope.annotations.filter (b) -> b isnt a

  _setupXDM: (options) ->
    $rootScope = @element.injector().get '$rootScope'

    # jschannel chokes FF and Chrome extension origins.
    if (options.origin.match /^chrome-extension:\/\//) or
        (options.origin.match /^resource:\/\//)
      options.origin = '*'

    provider = Channel.build options
        # Dodge toolbars [DISABLE]
        #@provider.getMaxBottom (max) =>
        #  @element.css('margin-top', "#{max}px")
        #  @element.find('.topbar').css("top", "#{max}px")
        #  @element.find('#gutter').css("margin-top", "#{max}px")
        #  @plugins.Heatmap.BUCKET_THRESHOLD_PAD += max

    provider

    .bind('publish', (ctx, args...) => this.publish args...)

    .bind('back', =>
      # Navigate "back" out of the interface.
      $rootScope.$apply =>
        return unless this.discardDrafts()
        this.hide()
    )

    .bind('open', =>
      # Pop out the sidebar
      $rootScope.$apply => this.show()
    )

    .bind('showViewer', (ctx, ids) =>
      ids ?= []
      return unless this.discardDrafts()
      $rootScope.$apply =>
        this.showViewer this._getAnnotationsFromIDs(ids)
    )

    .bind('updateViewer', (ctx, ids) =>
      ids ?= []
      $rootScope.$apply =>
        this.updateViewer this._getAnnotationsFromIDs(ids)
    )

    .bind('toggleViewerSelection', (ctx, ids) =>
      $rootScope.$apply =>
        this.toggleViewerSelection this._getAnnotationsFromIDs(ids)
    )

    .bind('setTool', (ctx, name) =>
      $rootScope.$apply => this.setTool name
    )

    .bind('setVisibleHighlights', (ctx, state) =>
      $rootScope.$apply => this.setVisibleHighlights state
    )

    .bind('addEmphasis', (ctx, ids=[]) =>
      this.addEmphasis this._getAnnotationsFromIDs ids
    )

    .bind('removeEmphasis', (ctx, ids=[]) =>
      this.removeEmphasis this._getAnnotationsFromIDs ids
    )

   # Look up an annotation based on the ID
  _getAnnotationFromID: (id) -> @threading.getContainer(id)?.message

   # Look up a list of annotations, based on their IDs
  _getAnnotationsFromIDs: (ids) -> this._getAnnotationFromID id for id in ids

  _setupWrapper: ->
    @wrapper = @element.find('#wrapper')
    this

  _setupDocumentEvents: ->
    document.addEventListener 'dragover', (event) =>
      @host?.notify
        method: 'dragFrame'
        params: event.screenX
    this

  # Override things not used in the angular version.
  _setupDynamicStyle: -> this
  _setupViewer: -> this
  _setupEditor: -> this

  # Override things not needed, because we don't access the document
  # with this instance
  _setupDocumentAccessStrategies: -> this
  _scan: -> this

  # (Optionally) put some HTML formatting around a quote
  getHtmlQuote: (quote) -> quote

  # Just some debug output
  loadAnnotations: (annotations) ->
    console.log "Loaded", annotations.length, "annotations."
    super

  # Do nothing in the app frame, let the host handle it.
  setupAnnotation: (annotation) ->
    annotation.highlights = []
    annotation

  toggleViewerSelection: (annotations=[]) =>
    annotations = annotations.filter (a) -> a?
    scope = @element.scope()
    # XOR this list to the current selection
    list = scope.annotations = scope.annotations.slice()
    for a in annotations
      index = list.indexOf a
      if index isnt -1
        list.splice index, 1
      else
        list.push a
    # View and sort the selection
    scope.applyView "Selection"
    scope.applySort scope.viewState.sort
    this

  updateViewer: (annotations=[]) =>
    annotations = annotations.filter (a) -> a?
    scope = @element.scope()
    commentFilter = angular.bind(this, this.isComment)
    comments = (scope.$root.annotations or []).filter(commentFilter)
    scope.annotations = annotations
    scope.applySort scope.viewState.sort
    scope.annotations = [scope.annotations..., comments...]
    this

  showViewer: (annotations=[]) =>
    location = @element.injector().get('$location')
    location.path('/viewer').replace()
    scope = @element.scope()
    scope.annotations = annotations
    scope.applyView 'Selection'
    scope.applySort scope.viewState.sort
    this.show()

  addEmphasis: (annotations=[]) =>
    annotations = annotations.filter (a) -> a? # Filter out null annotations
    for a in annotations
      a.$emphasis = true
    @element.injector().get('$rootScope').$digest()

  removeEmphasis: (annotations=[]) =>
    annotations = annotations.filter (a) -> a? # Filter out null annotations
    for a in annotations
      delete a.$emphasis
    @element.injector().get('$rootScope').$digest()

  clickAdder: =>
    for p in @providers
      p.channel.notify
        method: 'adderClick'

  showEditor: (annotation) =>
    this.show()
    @element.injector().invoke [
      '$location', '$rootScope', 'drafts', 'identity',
      ($location,   $rootScope,   drafts,   identity) =>
        @ongoing_edit = annotation

        unless this.plugins.Auth? and this.plugins.Auth.haveValidToken()
          $rootScope.$apply ->
            identity.request()
          for p in @providers
            p.channel.notify method: 'onEditorHide'
          return

        # Set the path
        search =
          id: annotation.id
          action: 'create'
        $location.path('/editor').search(search)

        # Store the draft
        drafts.add annotation

        # Digest the change
        $rootScope.$digest()
    ]
    this

  show: =>
    @element.scope().frame.visible = true

  hide: =>
    @element.scope().frame.visible = false

  isOpen: =>
    @element.scope().frame.visible

  patch_store: ->
    $location = @element.injector().get '$location'
    $rootScope = @element.injector().get '$rootScope'

    Store = Annotator.Plugin.Store

    # When the Store plugin is first instantiated, don't load annotations.
    # They will be loaded manually as entities are registered by participating
    # frames.
    Store.prototype.loadAnnotations = ->
      query = limit: 1000
      @annotator.considerSocialView.call @annotator, query

      entities = {}

      for p in @annotator.providers
        for uri in p.entities
          unless entities[uri]?
            console.log "Loading annotations for: " + uri
            entities[uri] = true
            this.loadAnnotationsFromSearch (angular.extend {}, query, uri: uri)

      this.entities = Object.keys(entities)

    # When the store plugin finishes a request, update the annotation
    # using a monkey-patched update function which updates the threading
    # if the annotation has a newly-assigned id and ensures that the id
    # is enumerable.
    Store.prototype.updateAnnotation = (annotation, data) =>
      unless Object.keys(data).length
        return

      if annotation.id? and annotation.id != data.id
        # Update the id table for the threading
        thread = @threading.getContainer annotation.id
        thread.id = data.id
        @threading.idTable[data.id] = thread
        delete @threading.idTable[annotation.id]

        # The id is no longer temporary and should be serialized
        # on future Store requests.
        Object.defineProperty annotation, 'id',
          configurable: true
          enumerable: true
          writable: true

        # If the annotation is loaded in a view, switch the view
        # to reference the new id.
        search = $location.search()
        if search? and search.id == annotation.id
          search.id = data.id
          $location.search(search).replace()

      # Update the annotation with the new data
      annotation = angular.extend annotation, data
      @plugins.Bridge?.updateAnnotation annotation

      # Give angular a chance to react
      $rootScope.$digest()

  considerSocialView: (query) ->
    switch @socialView.name
      when "none"
        # Sweet, nothing to do, just clean up previous filters
        console.log "Not applying any Social View filters."
        delete query.user
      when "single-player"
        if @plugins.Permissions?.user
          console.log "Social View filter: single player mode."
          query.user = @plugins.Permissions.user
        else
          console.log "Social View: single-player mode, but ignoring it, since not logged in."
          delete query.user
      else
        console.warn "Unsupported Social View: '" + @socialView.name + "'!"

  setTool: (name) =>
    return if name is @tool
    return unless this.discardDrafts()

    if name is 'highlight'
      # Check login state first
      unless @plugins.Permissions?.user
        scope = @element.scope()
        # If we are not logged in, start the auth process
        scope.ongoingHighlightSwitch = true
        @element.injector().get('identity').request()
        this.show()
        return

      this.socialView.name = 'single-player'
    else
      this.socialView.name = 'none'

    @tool = name
    this.publish 'setTool', name
    for p in @providers
      p.channel.notify
        method: 'setTool'
        params: name

  setVisibleHighlights: (state) =>
    return if state is @visibleHighlights
    @visibleHighlights = state
    this.publish 'setVisibleHighlights', state
    for p in @providers
      p.channel.notify
        method: 'setVisibleHighlights'
        params: state

  # Is this annotation a comment?
  isComment: (annotation) ->
    # No targets and no references means that this is a comment
    not (annotation.references?.length or annotation.target?.length)

  # Is this annotation a reply?
  isReply: (annotation) ->
    # The presence of references means that this is a reply
    annotation.references?.length

  # Discard all drafts, deleting unsaved annotations from the annotator
  discardDrafts: ->
    return @element.injector().get('drafts').discard()


class DraftProvider
  drafts: null

  constructor: ->
    this.drafts = []

  $get: -> this

  add: (draft, cb) -> @drafts.push {draft, cb}

  remove: (draft) ->
    remove = []
    for d, i in @drafts
      remove.push i if d.draft is draft
    while remove.length
      @drafts.splice(remove.pop(), 1)

  contains: (draft) ->
    for d in @drafts
      if d.draft is draft then return true
    return false

  isEmpty: -> @drafts.length is 0

  discard: ->
    text =
      switch @drafts.length
        when 0 then null
        when 1
          """You have an unsaved reply.

          Do you really want to discard this draft?"""
        else
          """You have #{@drafts.length} unsaved replies.

          Do you really want to discard these drafts?"""

    if @drafts.length is 0 or confirm text
      discarded = @drafts.slice()
      @drafts = []
      d.cb?() for d in discarded
      true
    else
      false


class ViewFilter
  # This object is the filter matching configuration used by the filter() function
  checkers:
    quote:
      autofalse: (annotation) -> return annotation.references?
      value: (annotation) ->
        for target in annotation.target
          return target.quote if target.quote?
        ''
      match: (term, value) -> return value.indexOf(term) > -1
    since:
      autofalse: (annotation) -> return not annotation.updated?
      value: (annotation) -> return annotation.updated
      match: (term, value) ->
        delta = Math.round((+new Date - new Date(value)) / 1000)
        return delta <= term
    tag:
      autofalse: (annotation) -> return not annotation.tags?
      value: (annotation) -> return annotation.tags
      match: (term, value) -> return value in term
    text:
      autofalse: (annotation) -> return not annotation.text?
      value: (annotation) -> return annotation.text
      match: (term, value) -> return value.indexOf(term) > -1
    uri:
      autofalse: (annotation) -> return not annotation.uri?
      value: (annotation) -> return annotation.uri
      match: (term, value) -> return value is term
    user:
      autofalse: (annotation) -> return not annotation.user?
      value: (annotation) ->
        # XXX: Hopefully there is a cleaner solution
        # XXX: To reach persona filter from here
        return (annotation.user?.match /^acct:([^@]+)@(.+)/)?[1]
      match: (term, value) -> return value is term
    any:
      fields: ['quote', 'text', 'tag', 'user']



  this.$inject = ['searchfilter']
  constructor: (searchfilter) ->
    @searchfilter = searchfilter

  _matches: (filter, value, match) ->
    matches = true

    for term in filter.terms
      unless match term, value
        matches = false
        if filter.operator is 'and'
          break
      else
        matches = true
        if filter.operator is 'or'
          break
    matches

  _arrayMatches: (filter, value, match) ->
    matches = true
    # Make copy for filtering
    copy = value.slice()

    copy = copy.filter (e) ->
      match filter.terms, e

    if (filter.operator is 'and' and copy.length < filter.terms.length) or
    (filter.operator is 'or' and not copy.length)
      matches = false
    matches

  _anyMatches: (filter, value, match) ->
    matchresult = []
    for term in filter.terms
      if angular.isArray value
          matchresult.push match value, term
      else
          matchresult.push match term, value
    matchresult

  _checkMatch: (filter, annotation, checker) ->
    autofalsefn = checker.autofalse
    return false if autofalsefn? and autofalsefn annotation

    value = checker.value annotation
    if angular.isArray value
      if filter.lowercase then value = value.map (e) -> e.toLowerCase()
      return @_arrayMatches filter, value, checker.match
    else
      value = value.toLowerCase() if filter.lowercase
      return @_matches filter, value, checker.match


  # Filters a set of annotations, according to a given query.
  # Inputs:
  #   annotations is the input list of annotations (array)
  #   query is the query string. It will be converted to faceted filter by the SearchFilter
  #
  # It'll handle the annotation matching by the returned facet configuration (operator, lowercase, etc.)
  # and the here configured @checkers. This @checkers object contains instructions how to verify the match.
  # Structure:
  # [facet_name]:
  #   autofalse: a function for a preliminary false match result
  #              (i.e. if the annotation does not even have a 'text' field, do not try to match the 'text' facet)
  #   value: a function to extract to facet value for the annotation.
  #         (i.e. for the quote facet it is the annotation.target.quote from the right target from the annotations)
  #   match: a function to check if the extracted value matches with the facet value
  #         (i.e. for the text facet it has to check that if the facet is a substring of the annotation.text or not.
  #
  # Returns a two-element list:
  # [
  #   matched annotation IDs list,
  #   the faceted filters
  # ]
  filter: (annotations, query) =>
    filters = @searchfilter.generateFacetedFilter query
    results = []

    # Check for given limit
    # Find the minimal
    limit = 0
    if filters.result.terms.length
      limit = filter.result.terms[0]
      for term in filter.result.terms
        if limit > term then limit = term

    # Convert terms to lowercase if needed
    for _, filter of filters
      if filter.lowercase then filter.terms.map (e) -> e.toLowerCase()

    # Now that this filter is called with the top level annotations, we have to add the children too
    annotationsWithChildren = []
    for annotation in annotations
      annotationsWithChildren.push annotation
      children = annotation.thread?.flattenChildren()
      if children?.length > 0
        for child in children
          annotationsWithChildren.push child

    for annotation in annotationsWithChildren
      matches = true
      #ToDo: What about given zero limit?
      # Limit reached
      if limit and results.length >= limit then break

      for category, filter of filters
        break unless matches
        terms = filter.terms
        # No condition for this category
        continue unless terms.length

        switch category
          when 'result'
            # Handled above
            continue
          when 'any'
            # Special case
            matchterms = []
            matchterms.push false for term in terms

            for field in @checkers.any.fields
              conf = @checkers[field]

              continue if conf.autofalse? and conf.autofalse annotation
              value = conf.value annotation
              if angular.isArray value
                if filter.lowercase
                  value = value.map (e) -> e.toLowerCase()
              else
                value = value.toLowerCase() if filter.lowercase
              matchresult = @_anyMatches filter, value, conf.match
              matchterms = matchterms.map (t, i) -> t or matchresult[i]

            # Now let's see what we got.
            matched = 0
            for _, value of matchterms
              matched++ if value

            if (filter.operator is 'or' and matched  > 0) or (filter.operator is 'and' and matched is terms.length)
              matches = true
            else
              matches  = false
          else
            # For all other categories
            matches = @_checkMatch filter, annotation, @checkers[category]
      if matches
        results.push annotation.id

    [results, filters]


angular.module('h.services', imports)
.provider('drafts', DraftProvider)
.service('annotator', Hypothesis)
.service('viewFilter', ViewFilter)
