<form action="/recover/complete" method="POST">
    <input type="hidden" name="token" value="{{.Token}}" />
    {{$passwordErrs := .ErrMap.password}}
    <div class="form-group{{if $passwordErrs}} has-error{{end}}">
        <div class="input-group">
            <span class="input-group-addon"><i class="fa fa-lock"></i></span>
            <input class="form-control" type="text" name="password" placeholder="Password" required />
        </div>
        {{range $err := $passwordErrs}}
            <span class="help-block">{{print $err}}</span>
        {{end}}
    </div>

    {{$confirmPasswordErrs := .ErrMap.confirmPassword}}
    <div class="form-group{{if $confirmPasswordErrs}} has-error{{end}}">
        <div class="input-group">
            <span class="input-group-addon"><i class="fa fa-lock"></i></span>
            <input class="form-control" type="text" name="confirmPassword" placeholder="Confirm Password" required />
        </div>
        {{range $err := $confirmPasswordErrs}}
            <span class="help-block">{{print $err}}</span>
        {{end}}
    </div>
    <button class="btn btn-primary btn-block" type="submit">Submit</button>
    <input type="hidden" name="{{.XSRFName}}" value="{{.XSRFToken}}" />
</form>