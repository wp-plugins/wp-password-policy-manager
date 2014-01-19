jQuery(document).ready(function(){
	
	if(window.wppm_ModifyForm){
		jQuery('#user_login').val(window.wppm_ModifyForm.CurrentUserLogin).attr('readonly', true);
		var p = jQuery('#user_pass').parents('p:first');
		p.find('label').contents()[0].textContent = window.wppm_ModifyForm.TextOldPass;
		var n = jQuery(p.html().replace(/user_pass/g, 'user_pass_new').replace(/pwd/g, 'user_pass_new'));
		n.contents()[0].textContent = window.wppm_ModifyForm.TextNewPass;
		var v = jQuery(p.html().replace(/user_pass/g, 'user_pass_vfy').replace(/pwd/g, 'user_pass_vfy'));
		v.contents()[0].textContent = window.wppm_ModifyForm.TextVerPass;
		p.after(jQuery('<p/>').append(n), jQuery('<p/>').append(v));
		jQuery('#wp-submit').val(window.wppm_ModifyForm.BtnChangeAndLogin);
	}
	
});