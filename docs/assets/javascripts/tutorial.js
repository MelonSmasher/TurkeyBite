// The tutorial's moving parts: steps to tick off, questions that answer back,
// and progress kept in this browser.
//
// A page marks them up in its Markdown:
//   <div class="tb-step" data-step="tour-1" markdown>...</div>     a step
//   <div class="tb-quiz" data-answer="2" markdown>                  a question,
//     <ol> of options, then <div class="tb-explain"> for afterwards  2 = the second option
//   <div class="tb-progress"></div>                                this page's progress
//   <div class="tb-modules"> of links to module pages              every module's progress
//   <a class="tb-try" href="/explore?q=...">                       open the console
//
// Progress is kept in localStorage under tb-tutorial:<step>, so it belongs to
// this browser, and nothing about it is sent anywhere.
(function () {
  "use strict";

  var PREFIX = "tb-tutorial:";

  function done(step) {
    try {
      return localStorage.getItem(PREFIX + step) === "done";
    } catch (e) {
      return false;
    }
  }

  function mark(step, value) {
    try {
      if (value) {
        localStorage.setItem(PREFIX + step, "done");
      } else {
        localStorage.removeItem(PREFIX + step);
      }
    } catch (e) {
      // Storage refused: progress is just not kept
    }
  }

  function countDone(steps) {
    var finished = 0;
    steps.forEach(function (step) {
      if (done(step.dataset.step)) {
        finished += 1;
      }
    });
    return finished;
  }

  function describe(finished, total) {
    if (total && finished === total) {
      return "All " + total + " steps done";
    }
    return finished + " of " + total + " steps done";
  }

  function bar(container, finished, total) {
    container.innerHTML = "";
    var label = document.createElement("div");
    label.className = "tb-progress-label";
    label.textContent = describe(finished, total);
    var track = document.createElement("div");
    track.className = "tb-progress-track";
    track.setAttribute("role", "progressbar");
    track.setAttribute("aria-valuemin", "0");
    track.setAttribute("aria-valuemax", String(total));
    track.setAttribute("aria-valuenow", String(finished));
    track.setAttribute("aria-label", label.textContent);
    var fill = document.createElement("div");
    fill.className = "tb-progress-fill";
    fill.style.width = (total ? Math.round((finished / total) * 100) : 0) + "%";
    track.appendChild(fill);
    container.appendChild(label);
    container.appendChild(track);
  }

  function pageProgress(root) {
    var steps = root.querySelectorAll(".tb-step[data-step]");
    var finished = countDone(steps);
    root.querySelectorAll(".tb-progress").forEach(function (el) {
      bar(el, finished, steps.length);
    });
  }

  function setUpStep(root, step) {
    var id = step.dataset.step;
    var toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "tb-step-toggle md-button";
    function show() {
      var isDone = done(id);
      step.classList.toggle("tb-step-done", isDone);
      toggle.setAttribute("aria-pressed", String(isDone));
      toggle.textContent = isDone ? "✓ Done" : "Mark this step done";
    }
    toggle.addEventListener("click", function () {
      mark(id, !done(id));
      show();
      pageProgress(root);
    });
    show();
    step.appendChild(toggle);
  }

  function setUpSteps(root) {
    root.querySelectorAll(".tb-step[data-step]").forEach(function (step) {
      if (!step.querySelector(".tb-step-toggle")) {
        setUpStep(root, step);
      }
    });
    pageProgress(root);
  }

  function reveal(explain) {
    if (explain) {
      explain.hidden = false;
    }
  }

  function answer(list, verdict, explain, chosen, right) {
    var kind = right ? "tb-right" : "tb-wrong";
    list.querySelectorAll(".tb-option").forEach(function (option) {
      option.classList.remove("tb-right", "tb-wrong");
    });
    chosen.classList.add(kind);
    verdict.textContent = right ? "Right." : "Not quite. Try another.";
    verdict.className = "tb-verdict " + kind;
    if (right) {
      reveal(explain);
    }
  }

  function setUpOption(list, verdict, explain, item, right) {
    var button = document.createElement("button");
    button.type = "button";
    button.className = "tb-option";
    while (item.firstChild) {
      button.appendChild(item.firstChild);
    }
    item.appendChild(button);
    button.addEventListener("click", function () {
      answer(list, verdict, explain, button, right);
    });
  }

  function setUpQuiz(quiz) {
    var list = quiz.querySelector("ol, ul");
    if (!list || quiz.dataset.ready) {
      return;
    }
    quiz.dataset.ready = "yes";
    var correct = parseInt(quiz.dataset.answer, 10);
    var explain = quiz.querySelector(".tb-explain");
    if (explain) {
      explain.hidden = true;
    }
    var verdict = document.createElement("p");
    verdict.className = "tb-verdict";
    verdict.setAttribute("aria-live", "polite");
    list.classList.add("tb-options");
    Array.prototype.forEach.call(list.children, function (item, index) {
      setUpOption(list, verdict, explain, item, index + 1 === correct);
    });
    list.parentNode.insertBefore(verdict, list.nextSibling);
  }

  function setUpQuizzes(root) {
    root.querySelectorAll(".tb-quiz[data-answer]").forEach(setUpQuiz);
  }

  function setUpTryLinks(root) {
    root.querySelectorAll("a.tb-try").forEach(function (link) {
      // One console tab, reused by every link, beside the tutorial. The
      // console is this site's own origin, and noopener would open a new
      // tab every time
      link.target = "tbconsole";
    });
  }

  // On the tutorial's front page, a module's progress, counted from the
  // steps on its own page so the totals can never disagree with it
  function countModule(link) {
    var holder = document.createElement("span");
    holder.className = "tb-module-progress";
    link.parentNode.appendChild(holder);
    fetch(link.href, { credentials: "same-origin" })
      .then(function (response) {
        return response.ok ? response.text() : "";
      })
      .then(function (html) {
        var page = new DOMParser().parseFromString(html, "text/html");
        var steps = page.querySelectorAll(".tb-step[data-step]");
        if (steps.length) {
          bar(holder, countDone(steps), steps.length);
        }
      })
      .catch(function () {
        // The module still links; it just shows no count
      });
  }

  function forget() {
    if (!window.confirm("Forget which tutorial steps you have done?")) {
      return;
    }
    try {
      Object.keys(localStorage).forEach(function (key) {
        if (key.indexOf(PREFIX) === 0) {
          localStorage.removeItem(key);
        }
      });
    } catch (e) {
      // Nothing was kept
    }
    window.location.reload();
  }

  function setUpModules(root) {
    root.querySelectorAll(".tb-modules a[href]").forEach(function (link) {
      if (!link.dataset.counted) {
        link.dataset.counted = "yes";
        countModule(link);
      }
    });
    root.querySelectorAll(".tb-reset").forEach(function (button) {
      if (!button.dataset.ready) {
        button.dataset.ready = "yes";
        button.addEventListener("click", forget);
      }
    });
  }

  function setUp() {
    var root = document.querySelector(".md-content") || document;
    setUpSteps(root);
    setUpQuizzes(root);
    setUpTryLinks(root);
    setUpModules(root);
  }

  // Material re-renders the page without a reload when instant navigation is
  // on, and announces each page on document$
  function start() {
    if (window.document$ && typeof window.document$.subscribe === "function") {
      window.document$.subscribe(setUp);
    } else if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", setUp);
    } else {
      setUp();
    }
  }

  start();
}());
