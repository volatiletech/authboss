<form action="/login" method="POST">
    <div class="form-group{{if .Error}} has-error{{end}}">
        <div class="input-group">
            <span class="input-group-addon"><i class="fa fa-user"></i></span>
            <input type="text" class="form-control" name="username" placeholder="Username" value="{{.Username}}">
        </div>
    </div>
    <div class="form-group{{if .Error}} has-error{{end}}">
        <div class="input-group">
            <span class="input-group-addon"><i class="fa fa-lock"></i></span>
            <input  type="password" class="form-control" name="password" placeholder="Password">
        </div>
        <span class="help-block">{{.Error}}</span>
    </div>
    {{if .ShowRemember}}
    <div class="checkbox">
        <label>
            <input type="checkbox" name="rm" value="true"> Remember Me
        </label>
    </div>
    {{end}}
    <button class="btn btn-primary btn-block" type="submit">Login</button>
    {{if .ShowRecover}}
    <a class="btn btn-link btn-block" type="submit" href="/recover">Recover Account</a>
    {{end}}
    <input type="hidden" name="{{.XSRFName}}" value="{{.XSRFToken}}" />
</form>