<form action="/recover" method="POST">
    {{$usernameErrs := .ErrMap.username}}
    <div class="form-group{{if $usernameErrs}} has-error{{end}}">
        <div class="input-group">
            <span class="input-group-addon"><i class="fa fa-user"></i></span>
            <input class="form-control" type="text" name="username" placeholder="Username" value="{{.Username}}" />
        </div>
        {{range $err := $usernameErrs}}
            <span class="help-block">{{print $err}}</span>
        {{end}}
    </div>

    {{$confirmUsernameErrs := .ErrMap.confirmUsername}}
    <div class="form-group{{if $confirmUsernameErrs}} has-error{{end}}">
        <div class="input-group">
            <span class="input-group-addon"><i class="fa fa-user"></i></span>
            <input class="form-control" type="text" name="confirmUsername" placeholder="Confirm Username" value="{{.ConfirmUsername}}" />
        </div>
        {{range $err := $confirmUsernameErrs}}
            <span class="help-block">{{print $err}}</span>
        {{end}}
    </div>
    
    <button class="btn btn-primary btn-block" type="submit">Recover</button>
    <a class="btn btn-link btn-block" type="submit" href="/login">Cancel</a>
    <input type="hidden" name="{{.XSRFName}}" value="{{.XSRFToken}}" />
</form>