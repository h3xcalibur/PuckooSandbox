<html>
    <?php include "head.php"; ?>
<body>
<?php include "header.php";?>
<p>Click on the tabs to see the report results:</p>
<div class="tab">
  <button class="tablinks" onclick="openTab(event, 'Summary')">Summary</button>
  <button class="tablinks" onclick="openTab(event, 'Static')">Static Analysis</button>
  <button class="tablinks" onclick="openTab(event, 'Dynamic')">Dymamic Analysis</button>
  <button class="tablinks" onclick="openTab(event, 'Network')">Network Analysis</button>
</div>

<div id="Summary" class="tabcontent">
  <h3>Summary</h3>
  <p>Important executable actions, screenshots and highlights.</p>

<form action="dispimages.php" method="post">
	<button class="btnPics" type="submit" value="Submit"/>Show Screenshots</button>
</form>

  <h4>Behavior Summary:</h4>
  <h4>Suspicious registry activity</h4>
   <table id="procsbehav">
        <tr>
            <th>Image path</th>
            <th>Event Type</th>
            <th>Details</th>
			<th>Description</th>
			<th>pid</th>
        </tr>
    </table>

  <h5>Suspicious registry activity</h5>
   <table id="procsbehav">
        <tr>
            <th>Image path</th>
            <th>Event Type</th>
            <th>Details</th>
			<th>Description</th>
			<th>pid</th>
        </tr>
    </table>

<br/><br/>

</div>

<div id="Network" class="tabcontent">
  <p>All connections that were made during analysis time.</p>
    <table id="network-table">
        <tr>
                        <th>UtcTime</th>
            <th>Process Path</th>
            <th>SourceIp</th>
            <th>SourcePortName</th>
            <th>SourcePort</th>
			<th>Protocol</th>
			<th>DestinationIp</th>
        </tr>
    </table>
</div>

<div id="Dynamic" class="tabcontent" >
	<div class="w3-container">
	  <h2>Select behaviour</h2>
	  <div class="w3-row">
		<a href="javascript:void(0)" onclick="openSubTab(event, 'registry');">
		  <div class="w3-third tablink w3-bottombar w3-hover-light-grey w3-padding">Registry - added\deleted keys</div>
		</a>
		<a href="javascript:void(0)" onclick="openSubTab(event, 'registry-mod');">
		  <div class="w3-third tablink w3-bottombar w3-hover-light-grey w3-padding">Registry - modified keys</div>
		</a>
		<a href="javascript:void(0)" onclick="openSubTab(event, 'createdprocs');">
		  <div class="w3-third tablink w3-bottombar w3-hover-light-grey w3-padding">Created Processes</div>
		</a>
		<a href="javascript:void(0)" onclick="openSubTab(event, 'createdfiles');">
		  <div class="w3-third tablink w3-bottombar w3-hover-light-grey w3-padding">Created Files</div>
		</a>
	  </div>

	  <div id="registry" class="w3-container subtab" style="display:none">
		<table id="registry-table">
		  <tr>
			<th>UtcTime</th>
			<th>TargetObject</th>
			<th>ProcessId</th>
			<th>EventType</th>
			<th>User name</th>
			<th>Image</th>
			<th>User identifier</th>
		  </tr>
		</table>
	  </div>

	  <div id="registry-mod" class="w3-container subtab" style="display:none">
		<table id="registry-mod-table">
		  <tr>
			<th>UtcTime</th>
			<th>TargetObject</th>
			<th>ProcessId</th>
			<th>EventType</th>
			<th>User name</th>
			<th>Image</th>
			<th>Details</th>
		  </tr>
		</table>
	  </div>

	  <div id="createdprocs" class="w3-container subtab" style="display:none">
		<p>All processes that were created during analysis time.</p>
		<table id="file-table">
		  <tr>
		  <th>UtcTime</th>
			<th>ParentCommandLine</th>
			<th>ParentImage</th>
			<th>ParentProcessId</th>
			<th>ProcessId</th>
			<th>Image</th>
			<th>CommandLine</th>
			<th>User</th>
			<th>Hashes</th>
		  </tr>
		</table>
	  </div>

	  <div id="createdfiles" class="w3-container subtab" style="display:none">
		<table id="file-created-table">
		  <tr>
			<th>UtcTime</th>
			<th>CreationUtcTime</th>
			<th>TargetFileName</th>
			<th>ProcessId</th>
			<th>Image</th>
			<th>User domain</th>
			<th>User name</th>
		  </tr>
		</table>
	  </div>

		</div>
	</div>

<div id="Static" class="tabcontent">
  <h3>Static Analysis</h3>
  <p>Information about the PE file: import table, hashes, etc.</p>
<table id="static-table">
        <tr>
            <th>sha256</th>
            <th>sha1</th>
            <th>md5</th>
            <th>size</th>
			<th>file type</th>
			<th>matches file type</th>
        </tr>
    </table>

<p>VT summary</p>
<table id="static-tableVT">
			<th>Detected by Symantec</th>
			<th>Detected by McaFee</th>
			<th>Detected by Microsoft</th>
			<th>virustotal total scans</th>
			<th>virustotal BAD detections</th>
</table>

<br /><br />
<form action="printIAT.php" method="post">
	<button class="btnPics" type="submit" value="Submit"/>Show Import Address Table</button>
</form>
</div>
<footer>by dana</footer>
</body>
</html>