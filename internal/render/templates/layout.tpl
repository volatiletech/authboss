<html>
<head>
    <link href="//netdna.bootstrapcdn.com/font-awesome/4.0.3/css/font-awesome.css" rel="stylesheet" />
    <link href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.1/css/bootstrap.min.css" rel="stylesheet" />
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/2.1.3/jquery.min.js"></script>
    <script src="//maxcdn.bootstrapcdn.com/bootstrap/3.3.2/js/bootstrap.min.js" type="text/javascript"></script>
</head>
<body>
<div class="container-fluid">
    {{if .FlashSuccess}}
    <div class="row">
        <div class="col-xs-offset-3 col-md-6">
            <div class="alert alert-success alert-dismissable" style="margin-top: 75px;">
                <button type="button" class="close" data-dismiss="alert"><span>&times;</span></button>
                {{print .FlashSuccess}}
            </div>
        </div>
    </div>
    {{end}}
    {{if .FlashError}}
    <div class="row">
        <div class="col-xs-offset-3 col-md-6">
            <div class="alert alert-danger alert-dismissable" style="margin-top: 75px;">
                <button type="button" class="close" data-dismiss="alert"><span>&times;</span></button>
                {{print .FlashError}}
            </div>
        </div>
    </div>
    {{end}}
    <div class="row" style="margin-top: 25px;">
        <div class="col-md-offset-4 col-md-4">
            <div class="panel panel-default">
                <div class="panel-heading"></div>
                <div class="panel-body">
                    {{template "authboss" .}}
                </div>
            </div>
        </div>
    </div>
</div>
</body>
</html>


