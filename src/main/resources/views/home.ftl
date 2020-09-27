<#--

    Copyright 2017-2019 original authors

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

-->
<!DOCTYPE html>
<html lang="en">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<head>
  <!-- Required meta tags -->
  <meta charset="utf-8">
  <meta content="initial-scale=1, shrink-to-fit=no, width=device-width" name="viewport">

  <!-- Add Material CSS, replace Bootstrap CSS -->
  <link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons">
  <link rel="stylesheet" href="https://code.getmdl.io/1.3.0/material.blue-yellow.min.css" />
  <script defer src="https://code.getmdl.io/1.3.0/material.min.js"></script>
  <script defer>
    function toggleShow(id, targetId) {
      let source = document.getElementById(id);
      let target = document.getElementById(targetId);
      target.innerText = source.innerText;
    }
  </script>
  <title>Home</title>
</head>
<body class="container">
<div style="horiz-align: center">
  <h4>Sessions</h4>
  <div class="data-table">
    <table class="mdl-data-table mdl-js-data-table">
      <thead>
      <tr>
        <th scope="col" class="mdl-data-table__cell--non-numeric">Session Id</th>
        <th scope="col" class="mdl-data-table__cell--non-numeric">Actions</th>
        <th scope="col" class="mdl-data-table__cell--non-numeric" style="width: 860px">Data</th>
      </tr>
      <thead>
      <tbody>
      <#list sessions as s>
        <tr>
          <td scope="row" class="mdl-data-table__cell--non-numeric">${s.state}</td>
          <td class="mdl-data-table__cell--non-numeric" style="horiz-align: center !important;">
            <#if s.connected && !s.ended>
              <a class="mdl-button mdl-js-button mdl-button--raised" href="/user-info/${s.state}">User Info</a>
              <br/>
              <a class="mdl-button mdl-js-button mdl-button--raised" href="/refresh-token/${s.state}">Refresh Token</a>
              <br/>
              <a class="mdl-button mdl-js-button mdl-button--raised" href="/logout/${s.state}">Logout</a>
            </#if>
            <#if (!s.connected && !s.ended && !s.failed)><a class="mdl-button mdl-js-button mdl-button--raised" href="${s.loginUri}">Login</a></#if>
            <#if s.connected && s.ended>Terminated</#if>
            <#if s.failed>Failed</#if>
          </td>
          <td class="mdl-data-table__cell--non-numeric">
            <div class="mdl-card mdl-shadow--2dp" style="width:100%; max-height: 300px; max-width: 850px">
              <div class="mdl-card__supporting-text" style="width: 100%; overflow: scroll; display: block">
                <pre id="${s.state}-target">${s.statusJson!''}</pre>
              </div>
            </div>
            <div class="mdl-card__actions mdl-card--border">
              <button class="mdl-button mdl-js-button mdl-js-ripple-effect" onclick="toggleShow('${s.state}-status', '${s.state}-target')">Status</button>
              <button class="mdl-button mdl-js-button mdl-js-ripple-effect" onclick="toggleShow('${s.state}-user-info', '${s.state}-target')">User Info</button>
              <button class="mdl-button mdl-js-button mdl-js-ripple-effect" onclick="toggleShow('${s.state}-response', '${s.state}-target')">Last Response</button>
            </div>
          </td>
        </tr>
      </#list>
      </tbody>
    </table>
  </div>
</div>
<div id="data" hidden="hidden">
  <#list sessions as s>
    <pre id="${s.state}-status">${s.statusJson!''}</pre>
    <pre id="${s.state}-user-info">${s.userInfoJson!''}</pre>
    <pre id="${s.state}-response">${s.responseJson!''}</pre>
  </#list>
</div>
</body>
</html>