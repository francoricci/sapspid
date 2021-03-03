function toggle() {
  let acc = document.getElementById("accordion");
  acc.classList.toggle("active");
  let panel = acc.nextElementSibling;
  if (panel.style.display === "block") {
    panel.style.display = "none";
  } else {
    panel.style.display = "block";
  }
};
