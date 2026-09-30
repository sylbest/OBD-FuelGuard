document.addEventListener('DOMContentLoaded', function () {
    const links = document.querySelectorAll('nav .nav-left a');
    links.forEach(function (link) {
        link.addEventListener('click', function () {
            links.forEach(l => l.classList.remove('active'));
            this.classList.add('active');
        });
    });
});