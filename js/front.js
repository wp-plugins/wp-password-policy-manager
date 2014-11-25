jQuery(document).ready(function(){

    if(window.wppm_ModifyForm){
        var d = window.wppm_ModifyForm;

        // update form fields
        jQuery('#user_login').val('').val(d.CurrentUserLogin).attr('readonly', true);
        var p = jQuery('#user_pass').val(d.CurrentUserPass).attr('readonly', true).parents('p:first');
        p.find('label').contents()[0].textContent = d.TextOldPass;

        // update form button
        jQuery('#wp-submit').val(d.BtnChangeAndLogin);

        // update form width + add rules
        var w = 280;
        if(d.NewPasswordRules.length){
            jQuery('#login').width(jQuery('#login').width() + w);
            jQuery('#loginform').css({'padding-right': w, 'position': 'relative'});
            var u = jQuery('<ul/>').css({'list-style': 'inside disc'});
            for(var i in d.NewPasswordRules)
                u.append(jQuery('<li/>').text(d.NewPasswordRules[i]));
            jQuery('#loginform').append(
                jQuery('<div/>').css({
                    'position': 'absolute',
                    'right': '24px',
                    'top': '188px',
                    'width': (w - 48) + 'px'
                }).append(
                    jQuery('<label/>').text(d.NewPassRulesHead),
                    u, jQuery('<div/>').html(d.NewPassRulesFoot).css({
                        'margin-top': '24px',
                        'font-size': '10px',
                        'font-weight': 'bold',
                        'line-height': '12px',
                        'text-align': 'center'
                    })
                )
            );
        }
    }
});