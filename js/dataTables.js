// Tables representing the data inside the tabs, by parsing the files
var request = new XMLHttpRequest();
request.open('GET', 'network.json');
request.send();
request.onload = function() {
// network tab - event id 3
var fileContent = JSON.parse(request.response);
var element = document.getElementById("Network");
	var table = document.getElementById('network-table');
	var smt = fileContent.hits.hits
	smt.forEach(function(object) {
	  var tr = document.createElement('tr');
	  tr.innerHTML += object._source.event_data.forEach(function(obj){
	    var td = document.createElement('td');
	    tr.innerHTML = '<td>' + obj + '</td>'
	  });

	  table.appendChild(tr);
});
}

// dynamic analysis tab
////process creation table - id 1
var request2 = new XMLHttpRequest();
request2.open('GET', 'file.json');
request2.send();
request2.onload = function() {
var sp = JSON.parse(request2.response);
var element2 = document.getElementById("Dynamic");
	var table2 = document.getElementById('file-table');

	var smt2 = sp.hits.hits
	smt2.forEach(function(object) {
	  var tr = document.createElement('tr');
	  tr.innerHTML = '<td>' + object._source.event_data.UtcTime + '</td>' +
		'<td>' + object._source.event_data.ParentCommandLine + '</td>' +
		'<td>' + object._source.event_data.ParentImage + '</td>' +
		'<td>' + object._source.event_data.ParentProcessId + '</td>' +
		'<td>' + object._source.event_data.ProcessId + '</td>'+
		'<td>' + object._source.event_data.Image + '</td>'+
		'<td>' + object._source.event_data.CommandLine + '</td>'+
		'<td>' + object._source.event_data.Hashes + '</td>'+
		'<td>' + object._source.event_data.User + '</td>';
	  table2.appendChild(tr);
});

}

////registry create\delete table: event ids: 12
var request3 = new XMLHttpRequest();
request3.open('GET', 'registry-created.json');
request3.send();
request3.onload = function() {
var sp3 = JSON.parse(request3.response);
var element2 = document.getElementById("Dynamic");
	var table3 = document.getElementById('registry-table');

	var smt3 = sp3.hits.hits
	smt3.forEach(function(object) {
	  var tr3 = document.createElement('tr');
	  tr3.innerHTML = '<td>' + object._source.event_data.UtcTime + '</td>' +
		'<td>' + object._source.event_data.TargetObject + '</td>' +
		'<td>' + object._source.event_data.ProcessId + '</td>' +
		'<td>' + object._source.event_data.EventType + '</td>' +
		'<td>' + object._source.user.name + '</td>'+
		'<td>' + object._source.event_data.Image + '</td>'+
		'<td>' + object._source.user.identifier + '</td>';
	  table3.appendChild(tr3);
});
}


////registr3y edit table: event ids: 13
var request4 = new XMLHttpRequest();
request4.open('GET', 'registry-edited.json');
request4.send();
request4.onload = function() {
var sp4 = JSON.parse(request4.response);
var element3 = document.getElementById("Dynamic");
	var table4 = document.getElementById('registry-mod-table');

	var smt4 = sp4.hits.hits
	smt4.forEach(function(object) {
	  var tr4 = document.createElement('tr');
	  tr4.innerHTML = '<td>' + object._source.event_data.UtcTime + '</td>' +
		'<td>' + object._source.event_data.TargetObject + '</td>' +
		'<td>' + object._source.event_data.ProcessId + '</td>' +
		'<td>' + object._source.event_data.EventType + '</td>' +
		'<td>' + object._source.user.name + '</td>'+
		'<td>' + object._source.event_data.Image + '</td>'+
		'<td>' + object._source.event_data.Details + '</td>';
	  table4.appendChild(tr4);
});
}

////static analysis
var request6 = new XMLHttpRequest();
request6.open('GET', 'static.json');
request6.send();
request6.onload = function() {
var sp6 = JSON.parse(request6.response);
var element6 = document.getElementById("Dynamic");
	var table6 = document.getElementById('static-table');

	var smt6 = sp6
	smt6.forEach(function(object) {
	  var tr6 = document.createElement('tr');
	  tr6.innerHTML = '<td>' + object.sha256 + '</td>' +
		'<td>' + object.sha1 + '</td>' +
		'<td>' + object.md5 + '</td>' +
		'<td>' + object.size + '</td>'+
		'<td>' + object.file_type + '</td>'+
		'<td>' + object.detectedbysymantec + '</td>' +
		'<td>' + object.detectedbymcafee + '</td>' +
		'<td>' + object.detectedbymicrosoft + '</td>' +
		'<td>' + object.virustotal + '</td>' +
		'<td>' + object.baddetections + '</td>' +
		'<td>' + object.matches_file_type + '</td>';
	  table6.appendChild(tr6);
});
}

////created files (11) table
var request5 = new XMLHttpRequest();
request5.open('GET', 'file_creation.json');
request5.send();
request5.onload = function() {
var sp5 = JSON.parse(request5.response);
var element5 = document.getElementById("Dynamic");
	var table5 = document.getElementById('file-created-table');

	var smt5 = sp5.hits.hits
	smt5.forEach(function(object) {
	  var tr5 = document.createElement('tr');
	  tr5.innerHTML = '<td>' + object._source.event_data.UtcTime + '</td>' +
		'<td>' + object._source.event_data.CreationUtcTime + '</td>' +
		'<td>' + object._source.event_data.TargetFilename + '</td>' +
		'<td>' + object._source.event_data.ProcessId + '</td>'+
		'<td>' + object._source.event_data.Image + '</td>'+
		'<td>' + object._source.user.domain + '</td>'+
		'<td>' + object._source.user.name + '</td>';
	  table5.appendChild(tr5);
});
}


////behaviour table processes
var request7 = new XMLHttpRequest();
request7.open('GET','registry-behavior.json');
request7.send();
request7.onload = function() {
var sp7 = JSON.parse(request7.response);
var element7 = document.getElementById("Dynamic");
	var table7 = document.getElementById('procsbehav');

	var smt7 = sp7
	smt7.forEach(function(object) {
	  var tr7 = document.createElement('tr');
	  tr7.innerHTML = '<td>' + object.bu + '</td>' +
		'<td>' + object.bl + '</td>' +
		'<td>' + object.bp + '</td>';
	  table7.appendChild(tr7);
});
}

