jQuery(function($){
    if(wppm_ModifyForm) {
        var form = $('#resetpassform'),data = form.html(), d = wppm_ModifyForm;
        form.html($('<div id="wp-reset-container"></div>').html(data));
        var u = $('<ul/>').css({'list-style': 'inside disc'});
        for (var i in d.NewPasswordRules)
            u.append($('<li/>').text(d.NewPasswordRules[i]));
        form.append(
            $('<div id="wp-reset-form-rules"></div>').append(
                $('<label/>').text(d.NewPassRulesHead),
                u, $('<div/>').html(d.NewPassRulesFoot).css({
                    'margin-top': '24px',
                    'font-size': '10px',
                    'font-weight': 'bold',
                    'line-height': '12px',
                    'text-align': 'center'
                })
            )
        );
    }
});