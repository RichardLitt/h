imports = [
  'ngAnimate'
  'ngRoute'
  'h.auth'
  'h.controllers'
  'h.controllers.AccountManagement'
  'h.directives'
  'h.directives.annotation'
  'h.filters'
  'h.identity'
  'h.streamsearch'
  'h.helpers.formHelpers'
]


configure = [
  '$locationProvider', '$provide', '$routeProvider', '$sceDelegateProvider',
  ($locationProvider,   $provide,   $routeProvider,   $sceDelegateProvider) ->
    $locationProvider.html5Mode(true)

    # Disable annotating while drafting
    $provide.decorator 'drafts', [
      'annotator', '$delegate',
      (annotator,   $delegate) ->
        {add, remove} = $delegate

        $delegate.add = (draft) ->
          add.call $delegate, draft
          annotator.disableAnnotating $delegate.isEmpty()

        $delegate.remove = (draft) ->
          remove.call $delegate, draft
          annotator.enableAnnotating $delegate.isEmpty()

        $delegate
      ]

    $routeProvider.when '/a/:id',
      controller: 'AnnotationViewerController'
      templateUrl: 'viewer.html'
    $routeProvider.when '/editor',
      controller: 'EditorController'
      templateUrl: 'editor.html'
    $routeProvider.when '/viewer',
      controller: 'ViewerController'
      templateUrl: 'viewer.html'
    $routeProvider.when '/page_search',
      controller: 'SearchController'
      templateUrl: 'page_search.html'
    $routeProvider.when '/stream',
      controller: 'StreamSearchController'
      templateUrl: 'viewer.html'
    $routeProvider.otherwise
      redirectTo: '/viewer'

    # Configure CSP for templates
    # XXX: IE workaround for the lack of document.baseURI property
    baseURI = document.baseURI
    if not baseURI
      baseTags = document.getElementsByTagName "base"
      baseURI = if baseTags.length then baseTags[0].href else document.URL

    # Explicitly whitelist '.html' paths adjacent to application base URI
    # TODO: move all front-end templates into their own directory for safety
    basePattern = baseURI.replace /\/[^\/]*$/, '/**.html'
    $sceDelegateProvider.resourceUrlWhitelist ['self', basePattern]
]


angular.module('h', imports, configure)
