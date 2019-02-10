<?php
$files = glob("screenshots/*.*");
if($_REQUEST[auto] == "on") {
    $meta = "<meta http-equiv=\"refresh\" content=\"2;url=$PHP_SELF?image=$next_img&amp;auto=on\" />
                    <meta http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-1\" />";
    $nav = "<a href=\"$PHP_SELF?image=$back_img&amp;auto=on\">Back</a> |
                 <a href=\"$PHP_SELF?image=$image&amp;auto=off\">Stop Slideshow</a> |                
                 <a href=\"$PHP_SELF?image=$next_img&amp;auto=on\">Next</a>";
}
if($_REQUEST[auto] == "off" || !$_REQUEST[auto]) {
    $meta = "   <meta http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-1\" />";
    $nav = "<a href=\"$PHP_SELF?image=$back_img&amp;auto=off\">Back</a> |
                 <a href=\"$PHP_SELF?image=$image&amp;auto=on\">Start Slideshow</a> |                
                 <a href=\"$PHP_SELF?image=$next_img&amp;auto=off\">Next</a>";
}

for ($i = 0; $i < count($files); $i++) {
    $image = $files[$i];
    echo<<<EOF
        <div class="pics fade" align="center">
        <img src="./$image" height=750 width=1150 /><br /><br />
        $nav
        </div>
EOF;
	//if(($i % 3) == 0) {echo "<br /><br />";}
}

echo<<<EOF
"<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="style/screenshots.css">
</head>
<body>
<div class="slideshow-container">
<div style="text-align:center">
  <span class="dot"></span> 
  <span class="dot"></span> 
  <span class="dot"></span> 
  <span class="dot"></span> 
  <span class="dot"></span> 
  <span class="dot"></span> 
  <span class="dot"></span> 
  <span class="dot"></span> 
  <span class="dot"></span> 
  <span class="dot"></span> 
  <span class="dot"></span> 
  <span class="dot"></span> 
  <span class="dot"></span> 
  <span class="dot"></span> 
  <span class="dot"></span> 
</div>

<script>
var slideIndex = 0;
showSlides();

function showSlides()
{
    var i;
    var slides = document.getElementsByClassName("pics");
    var dots = document.getElementsByClassName("dot");
    for (i = 0; i < slides.length; i++) {
       slides[i].style.display = "none";  
    }
    slideIndex++;
    if (slideIndex > slides.length) {slideIndex = 1}    
    for (i = 0; i < dots.length; i++) {
        dots[i].className = dots[i].className.replace(" active", "");
    }
    slides[slideIndex-1].style.display = "block";  
    dots[slideIndex-1].className += " active";
    setTimeout(showSlides, 2000); // Change image every 2 seconds
}
</script>
</body>
</html> 

EOF
?>