const $ = new DisplayJS(window);

$.on(".hamburger", "click", e => {
    if ($.getProp(".menu").css.top != "0px") {
        $.css(".menu", "top", "0")
        $.css(".hamburger", "color", "black")
        $.html(".hamburger", "<i class=\"fa fa-times\" aria-hidden=\"true\"></i>")
    } else {
        $.css(".menu", "top", "-100vh")
        $.css(".hamburger", "color", "white")
        $.html(".hamburger", "<i class=\"fa fa-bars\" aria-hidden=\"true\"></i>")
    }
})

$.scroll(() => {
    const distance = $.scrollTop();
    if (distance > window.innerHeight - 20) {
        $.css(".hamburger", "color", "black")
    } else {
        $.css(".hamburger", "color", "white")
    }
})

// Glottologist
const glot = new Glottologist();
glot.import("lang.json").then(() => {
	glot.render()
})
