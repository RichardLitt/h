imports = [
  'bootstrap'
  'h.controllers'
  'h.directives'
  'h.filters'
  'h.flash'
  'h.helpers'
  'h.searchfilters'
]

class StreamSearch
  this.inject = [
    '$scope', '$rootScope', '$q',
    'annotator', 'queryparser', 'searchfilter', 'streamfilter'
  ]
  constructor: (
     $scope,   $rootScope,   $q
     annotator,   queryparser,   searchfilter,   streamfilter
  ) ->
    # Initialize the base filter
    streamfilter
      .resetFilter()
      .setMatchPolicyIncludeAll()
      .setPastDataHits(50)

    # Apply query clauses
    terms = searchfilter.generateFacetedFilter $scope.search.query
    queryparser.populateFilter streamfilter, terms

    $scope.isEmbedded = false
    $scope.isStream = true

    $scope.sort.name = 'Newest'

    updater = $q.defer()

    # Not an ideal solution, ideally we should wait for all the app
    # initialization to finish before any controllers are created.
    $scope.$watch 'updater', (value) ->
      if value
        value.then (sock) -> updater.resolve(sock)

    $scope.$watch 'store.entities', ->
      updater.promise.then (sock) ->
        filter = streamfilter.getFilter()
        sock.send(JSON.stringify({filter}))

    $scope.shouldShowAnnotation = (id) ->
      # TODO: Determine if the annotation id provided is part of the current
      # search results...
      true


angular.module('h.streamsearch', imports, configure)
.controller('StreamSearchController', StreamSearch)
