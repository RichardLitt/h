// Generated by CoffeeScript 1.6.3
/*
** Annotator 1.2.6-dev-28f472f
** https://github.com/okfn/annotator/
**
** Copyright 2012 Aron Carroll, Rufus Pollock, and Nick Stenning.
** Dual licensed under the MIT and GPLv3 licenses.
** https://github.com/okfn/annotator/blob/master/LICENSE
**
** Built at: 2014-01-13 23:48:42Z
*/



/*
//
*/

// Generated by CoffeeScript 1.6.3
(function() {
  var Anchor, DummyDocumentAccess, EnhancedAnchoringManager, Highlight, _ref,
    __bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; },
    __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    __indexOf = [].indexOf || function(item) { for (var i = 0, l = this.length; i < l; i++) { if (i in this && this[i] === item) return i; } return -1; };

  Anchor = (function() {
    function Anchor(annotator, annotation, target, startPage, endPage, quote, diffHTML, diffCaseOnly) {
      var pageIndex, _base, _i, _ref, _ref1;
      this.annotator = annotator;
      this.annotation = annotation;
      this.target = target;
      this.startPage = startPage;
      this.endPage = endPage;
      this.quote = quote;
      this.diffHTML = diffHTML;
      this.diffCaseOnly = diffCaseOnly;
      this.virtualize = __bind(this.virtualize, this);
      this.realize = __bind(this.realize, this);
      if (this.annotator == null) {
        throw "annotator is required!";
      }
      if (this.annotation == null) {
        throw "annotation is required!";
      }
      if (this.target == null) {
        throw "target is required!";
      }
      if (this.startPage == null) {
        "startPage is required!";
      }
      if (this.endPage == null) {
        throw "endPage is required!";
      }
      if (this.quote == null) {
        throw "quote is required!";
      }
      this.highlight = {};
      this.target.quote = this.quote;
      this.target.diffHTML = this.diffHTML;
      this.target.diffCaseOnly = this.diffCaseOnly;
      this.annotation.anchors.push(this);
      this.Util = Annotator.Util;
      this.Util.removeFromSet(this.annotation, this.annotator.anchoring.orphans);
      if (this.annotation.anchors.length === this.annotation.target.length) {
        this.Util.removeFromSet(this.annotation, this.annotator.anchoring.halfOrphans);
      } else {
        this.Util.addToSet(this.annotation, this.annotator.anchoring.halfOrphans);
      }
      for (pageIndex = _i = _ref = this.startPage, _ref1 = this.endPage; _ref <= _ref1 ? _i <= _ref1 : _i >= _ref1; pageIndex = _ref <= _ref1 ? ++_i : --_i) {
        if ((_base = this.annotator.anchoring.anchors)[pageIndex] == null) {
          _base[pageIndex] = [];
        }
        this.annotator.anchoring.anchors[pageIndex].push(this);
      }
    }

    Anchor.prototype._createHighlight = function(page) {
      throw "Function not implemented";
    };

    Anchor.prototype.realize = function() {
      var created, error, hlError, page, pagesTodo, renderedPages, _i, _j, _len, _ref, _ref1, _results, _results1,
        _this = this;
      if (this.fullyRealized) {
        return;
      }
      renderedPages = (function() {
        _results = [];
        for (var _i = _ref = this.startPage, _ref1 = this.endPage; _ref <= _ref1 ? _i <= _ref1 : _i >= _ref1; _ref <= _ref1 ? _i++ : _i--){ _results.push(_i); }
        return _results;
      }).apply(this).filter(function(index) {
        return _this.annotator.anchoring.domMapper.isPageMapped(index);
      });
      pagesTodo = renderedPages.filter(function(index) {
        return _this.highlight[index] == null;
      });
      if (!pagesTodo.length) {
        return;
      }
      try {
        created = (function() {
          var _j, _len, _results1;
          _results1 = [];
          for (_j = 0, _len = pagesTodo.length; _j < _len; _j++) {
            page = pagesTodo[_j];
            _results1.push(this.highlight[page] = this._createHighlight(page));
          }
          return _results1;
        }).call(this);
        this.fullyRealized = renderedPages.length === this.endPage - this.startPage + 1;
        return this.annotator.publish('highlightsCreated', created);
      } catch (_error) {
        error = _error;
        console.log("Error while trying to create highlight:", error.stack);
        this.fullyRealized = false;
        _results1 = [];
        for (_j = 0, _len = pagesTodo.length; _j < _len; _j++) {
          page = pagesTodo[_j];
          if (this.highlight[page]) {
            try {
              this.highlight[page].removeFromDocument();
              _results1.push(console.log("Removed broken HL from page", page));
            } catch (_error) {
              hlError = _error;
              _results1.push(console.log("Could not remove broken HL from page", page, ":", hlError.stack));
            }
          }
        }
        return _results1;
      }
    };

    Anchor.prototype.virtualize = function(pageIndex) {
      var error, highlight;
      highlight = this.highlight[pageIndex];
      if (highlight == null) {
        return;
      }
      try {
        highlight.removeFromDocument();
      } catch (_error) {
        error = _error;
        console.log("Could not remove HL from page", pageIndex, ":", error.stack);
      }
      delete this.highlight[pageIndex];
      this.fullyRealized = false;
      return this.annotator.publish('highlightRemoved', highlight);
    };

    Anchor.prototype.remove = function() {
      var anchors, index, _i, _ref, _ref1;
      for (index = _i = _ref = this.startPage, _ref1 = this.endPage; _ref <= _ref1 ? _i <= _ref1 : _i >= _ref1; index = _ref <= _ref1 ? ++_i : --_i) {
        this.virtualize(index);
        anchors = this.annotator.anchoring.anchors[index];
        this.Util.removeFromSet(this, anchors);
        if (!anchors.length) {
          delete this.annotator.anchoring.anchors[index];
        }
      }
      this.Util.removeFromSet(this, this.annotation.anchors);
      if (this.annotation.anchors.length) {
        return this.Util.addToSet(this.annotation, this.annotator.anchoring.halfOrphans);
      } else {
        this.Util.addToSet(this.annotation, this.annotator.anchoring.orphans);
        return this.Util.removeFromSet(this.annotation, this.annotator.anchoring.halfOrphans);
      }
    };

    Anchor.prototype.verify = function(reason, data) {
      var dfd, error,
        _this = this;
      dfd = Annotator.$.Deferred();
      if (this.strategy.verify) {
        try {
          this.strategy.verify(this, reason, data).then(function(valid) {
            if (!valid) {
              _this.remove();
            }
            return dfd.resolve();
          });
        } catch (_error) {
          error = _error;
          console.log("Error while executing", this.constructor.name, "'s verify method:", error.stack);
          this.remove();
          dfd.resolve();
        }
      } else {
        console.log("Can't verify this", this.constructor.name, "because the", "'" + this.strategy.name + "'", "strategy (which was responsible for creating this anchor)", "did not specify a verify function.");
        this.remove();
        dfd.resolve();
      }
      return dfd.promise();
    };

    Anchor.prototype.annotationUpdated = function() {
      var index, _i, _ref, _ref1, _ref2, _results;
      _results = [];
      for (index = _i = _ref = this.startPage, _ref1 = this.endPage; _ref <= _ref1 ? _i <= _ref1 : _i >= _ref1; index = _ref <= _ref1 ? ++_i : --_i) {
        _results.push((_ref2 = this.highlight[index]) != null ? _ref2.annotationUpdated() : void 0);
      }
      return _results;
    };

    return Anchor;

  })();

  Highlight = (function() {
    function Highlight(anchor, pageIndex) {
      this.anchor = anchor;
      this.pageIndex = pageIndex;
      this.annotator = this.anchor.annotator;
      this.annotation = this.anchor.annotation;
    }

    Highlight.prototype.setTemporary = function(value) {
      throw "Operation not implemented.";
    };

    Highlight.prototype.isTemporary = function() {
      throw "Operation not implemented.";
    };

    Highlight.prototype.setActive = function(value, batch) {
      if (batch == null) {
        batch = false;
      }
      throw "Operation not implemented.";
    };

    Highlight.prototype.annotationUpdated = function() {};

    Highlight.prototype.removeFromDocument = function() {
      throw "Operation not implemented.";
    };

    Highlight.prototype._getDOMElements = function() {
      throw "Operation not implemented.";
    };

    Highlight.prototype.getTop = function() {
      return $(this._getDOMElements()).offset().top;
    };

    Highlight.prototype.getHeight = function() {
      return $(this._getDOMElements()).outerHeight(true);
    };

    Highlight.prototype.getBottom = function() {
      return this.getTop() + this.getBottom();
    };

    Highlight.prototype.scrollTo = function() {
      return $(this._getDOMElements()).scrollintoview();
    };

    Highlight.prototype.paddedScrollTo = function(direction) {
      var defaultView, dir, pad, where, wrapper;
      if (direction == null) {
        throw "Direction is required";
      }
      dir = direction === "up" ? -1 : +1;
      where = $(this._getDOMElements());
      wrapper = this.annotator.wrapper;
      defaultView = wrapper[0].ownerDocument.defaultView;
      pad = defaultView.innerHeight * .2;
      return where.scrollintoview({
        complete: function() {
          var correction, scrollable, top;
          scrollable = this.parentNode === this.ownerDocument ? $(this.ownerDocument.body) : $(this);
          top = scrollable.scrollTop();
          correction = pad * dir;
          return scrollable.stop().animate({
            scrollTop: top + correction
          }, 300);
        }
      });
    };

    Highlight.prototype.paddedScrollUpTo = function() {
      return this.paddedScrollTo("up");
    };

    Highlight.prototype.paddedScrollDownTo = function() {
      return this.paddedScrollTo("down");
    };

    return Highlight;

  })();

  DummyDocumentAccess = (function() {
    function DummyDocumentAccess(rootNode) {
      this.rootNode = rootNode;
    }

    DummyDocumentAccess.applicable = function() {
      return true;
    };

    DummyDocumentAccess.prototype.getPageIndex = function() {
      return 0;
    };

    DummyDocumentAccess.prototype.getPageCount = function() {
      return 1;
    };

    DummyDocumentAccess.prototype.getPageRoot = function() {
      return this.rootNode;
    };

    DummyDocumentAccess.prototype.getPageIndexForPos = function() {
      return 0;
    };

    DummyDocumentAccess.prototype.isPageMapped = function() {
      return true;
    };

    return DummyDocumentAccess;

  })();

  EnhancedAnchoringManager = (function(_super) {
    __extends(EnhancedAnchoringManager, _super);

    function EnhancedAnchoringManager(annotator) {
      this.annotator = annotator;
      this._reanchorAllAnnotations = __bind(this._reanchorAllAnnotations, this);
      this._verifyAllAnchors = __bind(this._verifyAllAnchors, this);
      console.log("Initializing Enhanced Anchoring Manager");
      this.anchoringStrategies = [];
      this._setupDocumentAccessStrategies();
      this._setupAnchorEvents();
      this.orphans = [];
      this.halfOrphans = [];
    }

    EnhancedAnchoringManager.prototype._setupDocumentAccessStrategies = function() {
      var _this = this;
      return this.documentAccessStrategies = [
        {
          name: "Dummy",
          applicable: function() {
            return true;
          },
          get: function() {
            return new DummyDocumentAccess(_this.wrapper[0]);
          }
        }
      ];
    };

    EnhancedAnchoringManager.prototype._setupAnchorEvents = function() {
      var _this = this;
      return this.annotator.on('annotationUpdated', function(annotation) {
        var anchor, _i, _len, _ref, _results;
        _ref = annotation.anchors || [];
        _results = [];
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          anchor = _ref[_i];
          _results.push(anchor.annotationUpdated());
        }
        return _results;
      });
    };

    EnhancedAnchoringManager.prototype._chooseAccessPolicy = function() {
      var s, _i, _len, _ref,
        _this = this;
      if (this.domMapper) {
        return;
      }
      _ref = this.documentAccessStrategies;
      for (_i = 0, _len = _ref.length; _i < _len; _i++) {
        s = _ref[_i];
        if (s.applicable()) {
          this.documentAccessStrategy = s;
          console.log("Selected document access strategy: " + s.name);
          this.domMapper = s.get();
          this.anchors = {};
          addEventListener("docPageMapped", function(evt) {
            return _this._realizePage(evt.pageIndex);
          });
          addEventListener("docPageUnmapped", function(evt) {
            return _this._virtualizePage(evt.pageIndex);
          });
          return this;
        }
      }
    };

    EnhancedAnchoringManager.prototype._createAnchorWithStrategies = function(annotation, target, strategies, promise) {
      var error, iteration, onFail, s,
        _this = this;
      s = strategies.shift();
      onFail = function(error) {
        if (strategies.length) {
          return _this._createAnchorWithStrategies(annotation, target, strategies, promise);
        } else {
          return promise.reject();
        }
      };
      try {
        iteration = s.create(annotation, target);
        iteration.then(function(anchor) {
          anchor.strategy = s;
          return promise.resolve(anchor);
        }).fail(onFail);
      } catch (_error) {
        error = _error;
        console.log("While trying anchoring strategy", "'" + s.name + "':");
        console.log(error.stack);
        onFail("see exception above");
      }
      return null;
    };

    EnhancedAnchoringManager.prototype._createAnchor = function(annotation, target) {
      var dfd;
      if (target == null) {
        throw new Error("Trying to find anchor for null target!");
      }
      dfd = Annotator.$.Deferred();
      this._createAnchorWithStrategies(annotation, target, this.anchoringStrategies.slice(), dfd);
      return dfd.promise();
    };

    EnhancedAnchoringManager.prototype._findAnchorForTarget = function(annotation, target) {
      var anchor, _i, _len, _ref;
      _ref = annotation.anchors;
      for (_i = 0, _len = _ref.length; _i < _len; _i++) {
        anchor = _ref[_i];
        if (anchor.target === target) {
          return anchor;
        }
      }
      return null;
    };

    EnhancedAnchoringManager.prototype._hasAnchorForTarget = function(annotation, target) {
      var anchor;
      anchor = this._findAnchorForTarget(annotation, target);
      return anchor != null;
    };

    EnhancedAnchoringManager.prototype._anchorAnnotation = function(annotation, targetFilter, publishEvent) {
      var dfd, index, promises, shouldDo, t, _ref,
        _this = this;
      if (publishEvent == null) {
        publishEvent = false;
      }
      if (targetFilter == null) {
        targetFilter = function(target) {
          return true;
        };
      }
      shouldDo = function(target) {
        return (!_this._hasAnchorForTarget(annotation, target)) && (targetFilter(target));
      };
      annotation.quote = (function() {
        var _i, _len, _ref, _results;
        _ref = annotation.target;
        _results = [];
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          t = _ref[_i];
          _results.push(t.quote);
        }
        return _results;
      })();
      if (annotation.anchors == null) {
        annotation.anchors = [];
      }
      promises = (function() {
        var _i, _len, _ref, _results,
          _this = this;
        _ref = annotation.target;
        _results = [];
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          t = _ref[_i];
          if (!(shouldDo(t))) {
            continue;
          }
          index = annotation.target.indexOf(t);
          _results.push(this._createAnchor(annotation, t).then(function(anchor) {
            annotation.quote[index] = t.quote;
            return anchor.realize();
          }));
        }
        return _results;
      }).call(this);
      dfd = Annotator.$.Deferred();
      (_ref = Annotator.$).when.apply(_ref, promises).always(function() {
        var p;
        annotation.quote = annotation.quote.filter(function(q) {
          return q != null;
        }).join(' / ');
        if (__indexOf.call((function() {
          var _i, _len, _results;
          _results = [];
          for (_i = 0, _len = promises.length; _i < _len; _i++) {
            p = promises[_i];
            _results.push(p.state());
          }
          return _results;
        })(), "resolved") >= 0) {
          if (_this.changedAnnotations != null) {
            _this.changedAnnotations.push(annotation);
          }
          if (publishEvent) {
            _this.publish("annotationsLoaded", [[annotation]]);
          }
        }
        return dfd.resolve(annotation);
      });
      return dfd.promise();
    };

    EnhancedAnchoringManager.prototype._anchorAllAnnotations = function(targetFilter) {
      var annotation, annotations, dfd, promises, _ref,
        _this = this;
      dfd = Annotator.$.Deferred();
      annotations = this.halfOrphans.concat(this.orphans);
      this.changedAnnotations = [];
      promises = (function() {
        var _i, _len, _results;
        _results = [];
        for (_i = 0, _len = annotations.length; _i < _len; _i++) {
          annotation = annotations[_i];
          _results.push(this._anchorAnnotation(annotation, targetFilter));
        }
        return _results;
      }).call(this);
      (_ref = Annotator.$).when.apply(_ref, promises).always(function() {
        if (_this.changedAnnotations.length) {
          _this.publish("annotationsLoaded", [_this.changedAnnotations]);
        }
        delete _this.changedAnnotations;
        return dfd.resolve();
      });
      return dfd.promise();
    };

    EnhancedAnchoringManager.prototype.getHighlights = function(annotations) {
      var anchor, anchors, annotation, hl, page, results, _i, _j, _len, _len1, _ref, _ref1, _ref2;
      results = [];
      if (annotations != null) {
        for (_i = 0, _len = annotations.length; _i < _len; _i++) {
          annotation = annotations[_i];
          _ref = annotation.anchors;
          for (_j = 0, _len1 = _ref.length; _j < _len1; _j++) {
            anchor = _ref[_j];
            _ref1 = anchor.highlight;
            for (page in _ref1) {
              hl = _ref1[page];
              results.push(hl);
            }
          }
        }
      } else {
        _ref2 = this.anchors;
        for (page in _ref2) {
          anchors = _ref2[page];
          $.merge(results, (function() {
            var _k, _len2, _results;
            _results = [];
            for (_k = 0, _len2 = anchors.length; _k < _len2; _k++) {
              anchor = anchors[_k];
              if (anchor.highlight[page] != null) {
                _results.push(anchor.highlight[page]);
              }
            }
            return _results;
          })());
        }
      }
      return results;
    };

    EnhancedAnchoringManager.prototype._realizePage = function(index) {
      var anchor, _i, _len, _ref, _ref1, _results;
      if (!this.domMapper.isPageMapped(index)) {
        return;
      }
      _ref1 = (_ref = this.anchors[index]) != null ? _ref : [];
      _results = [];
      for (_i = 0, _len = _ref1.length; _i < _len; _i++) {
        anchor = _ref1[_i];
        _results.push(anchor.realize());
      }
      return _results;
    };

    EnhancedAnchoringManager.prototype._virtualizePage = function(index) {
      var anchor, _i, _len, _ref, _ref1, _results;
      _ref1 = (_ref = this.anchors[index]) != null ? _ref : [];
      _results = [];
      for (_i = 0, _len = _ref1.length; _i < _len; _i++) {
        anchor = _ref1[_i];
        _results.push(anchor.virtualize(index));
      }
      return _results;
    };

    EnhancedAnchoringManager.prototype._verifyAllAnchors = function(reason, data) {
      var anchor, anchors, dfd, page, promises, _i, _len, _ref, _ref1, _ref2;
      if (reason == null) {
        reason = "no reason in particular";
      }
      if (data == null) {
        data = null;
      }
      dfd = Annotator.$.Deferred();
      promises = [];
      _ref = this.anchors;
      for (page in _ref) {
        anchors = _ref[page];
        _ref1 = anchors.slice();
        for (_i = 0, _len = _ref1.length; _i < _len; _i++) {
          anchor = _ref1[_i];
          promises.push(anchor.verify(reason, data));
        }
      }
      (_ref2 = Annotator.$).when.apply(_ref2, promises).always(function() {
        return dfd.resolve();
      });
      return dfd.promise();
    };

    EnhancedAnchoringManager.prototype._reanchorAllAnnotations = function(reason, data, targetFilter) {
      var dfd,
        _this = this;
      if (reason == null) {
        reason = "no reason in particular";
      }
      if (data == null) {
        data = null;
      }
      if (targetFilter == null) {
        targetFilter = null;
      }
      dfd = Annotator.$.Deferred();
      this._verifyAllAnchors(reason, data).then(function() {
        return _this._anchorAllAnnotations(targetFilter).then(function() {
          return dfd.resolve();
        });
      });
      return dfd.promise();
    };

    EnhancedAnchoringManager.prototype.init = function() {
      return this._chooseAccessPolicy();
    };

    EnhancedAnchoringManager.prototype.onSetup = function(annotation) {
      this.orphans.push(annotation);
      return this._anchorAnnotation(annotation);
    };

    EnhancedAnchoringManager.prototype.onDelete = function(annotation) {
      var a, _i, _len, _ref;
      if (annotation.anchors != null) {
        _ref = annotation.anchors;
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          a = _ref[_i];
          a.remove();
        }
      }
      return Annotator.Util.removeFromSet(annotation, this.orphans);
    };

    EnhancedAnchoringManager.prototype.onSetTemporary = function(annotation, value) {
      var hl, _i, _len, _ref, _results;
      _ref = this.getHighlights([annotation]);
      _results = [];
      for (_i = 0, _len = _ref.length; _i < _len; _i++) {
        hl = _ref[_i];
        _results.push(hl.setTemporary(value));
      }
      return _results;
    };

    return EnhancedAnchoringManager;

  })(Annotator.AnchoringManager);

  Annotator.Plugin.EnhancedAnchoring = (function(_super) {
    __extends(EnhancedAnchoring, _super);

    function EnhancedAnchoring() {
      _ref = EnhancedAnchoring.__super__.constructor.apply(this, arguments);
      return _ref;
    }

    EnhancedAnchoring.prototype.pluginInit = function() {
      return this.annotator.anchoring = new EnhancedAnchoringManager(this.annotator);
    };

    return EnhancedAnchoring;

  })(Annotator.Plugin);

  Annotator.Highlight = Highlight;

  Annotator.Anchor = Anchor;

}).call(this);

//
//@ sourceMappingURL=annotator.enhancedanchoring.map