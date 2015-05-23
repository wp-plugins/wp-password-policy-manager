jQuery(document).ready(function(){
	var RemoveSecToken = function(){
		var $this = jQuery(this).parents('span:first');
		$this.addClass('sectoken-del').fadeOut('fast', function(){
			$this.remove();
		});
	};
	
	jQuery('#ExemptTokenQueryBox').keydown(function(event){
		if(event.keyCode === 13) {
			jQuery('#ExemptTokenQueryAdd').click();
			return false;
		}
	});
	
	jQuery('#ExemptTokenQueryAdd').click(function(){
		var value = jQuery.trim(jQuery('#ExemptTokenQueryBox').val());
		var existing = jQuery('#ExemptTokenList input').filter(function() { return this.value === value; });
		
		if(!value || existing.length)return; // if value is empty or already used, stop here
		
		jQuery('#ExemptTokenQueryBox, #ExemptTokenQueryAdd').attr('disabled', true);
		jQuery.post(jQuery('#ajaxurl').val(), {action: 'check_security_token', token: value}, function(data){
			jQuery('#ExemptTokenQueryBox, #ExemptTokenQueryAdd').attr('disabled', false);
			if(data==='other' && !confirm('The specified token is not a user nor a role, do you still want to add it?'))return;
			jQuery('#ExemptTokenQueryBox').val('');
			jQuery('#ExemptTokenList').append(jQuery('<span class="sectoken-'+data+'"/>').text(value).append(
				jQuery('<input type="hidden" name="ExemptTokens[]"/>').val(value),
				jQuery('<a href="javascript:;" title="Remove">&times;</a>').click(RemoveSecToken)
			));
		});
	});
	
	jQuery('#ExemptTokenList>span>a').click(RemoveSecToken);
});