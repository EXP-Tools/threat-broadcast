<!-- RELEASE TIME : %(datetime)s -->
<html lang="zh-cn">

 <head>
  <meta charset="UTF-8" />
  <meta name="robots" content="noarchive" />
  <link rel="shortcut icon" href="https://exp-blog.com/favicon.png"/>
  <meta name="author" content="EXP: www.exp-blog.com" />
  <link rel="stylesheet" type="text/css" href="./css/page.css" />
  <title>Threat-Broadcast</title>
 </head>

 <body class="html">

  <div>
   <br />
   <h2><a href="https://exp-blog.com" target="_blank">眈眈探求</a> | <a href="https://github.com/lyy289065406/threat-broadcast">威胁情报播报</a></h2>
   <br />

   <p>页面生成时间：%(datetime)s。各来源的情报日期见 TIME 列；仅展示已启用且近期有有效情报的来源。</p>
   %(source_status)s

%(table)s

  </div>


<!--
  <br />
  <br />
  <br />

  <h2><font color="red">赞助途径</font></h2>
  <div style="text-align: center;">
    <table id="donate" style="margin: auto;">
      <tbody>
        <tr>
          <th><img src="imgs/alipay.png"/></th>
          <th><img src="imgs/wechat.png"/></th>
        </tr>
        <tr>
          <td style="text-align: center;">支付宝</td>
          <td style="text-align: center;">微信</td>
        </tr>
      </tbody>
    </table>
  </div>
-->
  <br />
 </body>
</html>
