/*
 * SingleID plugin for Wordpress without SSL -> https://github.com/SingleID/wordpress-plugin/
 * 
 * 
 */
 
 
var sid_div;
var sid_domain = document.domain;
var singleIDInterval;



function sid_sendData()
{

	
	var single_id = jQuery('input[name="SingleID"]').val();
	console.log('single_id: '+single_id);

		// we need to create a string with all the field with SingleIDAuth class -> 2015-03-25 -> To put in white-paper
		var AuthArray = {};
		
		$(jQuery('.SingleIDAuth')).each(function() {
			AuthArray[$(this).attr('id')] = $(this).val();
		});
		var AuthString = JSON.stringify(AuthArray);
		// console.log(AuthString);
		
	if(single_id)
	{
		jQuery.post(ajaxurl, 	{
								single_id:single_id,
								security: ajaxnonce,
								action: 'first_class_login',
								optionalAuth:AuthString,
								op: 'send'
								}, function(response) {
		
		console.log('Got this from the server: ' + response);
		
		
		if (isNaN(response)) {
			// console.log('isNaN true');
			clearInterval(singleIDInterval);
			jQuery('.singleid_waiting').html(response);
		}else{
			singleIDInterval = setInterval(sid_refresh, 2000);
			// console.log('isNaN false');
		}
		
		});
		
		jQuery('.singleid_waiting').html('waiting for data').show();
	}
}




function sid_refresh()
{
	console.log('refreshed!');
	var bcry = jQuery.cookie("bcry");
	
	jQuery.post(ajaxurl, {action: 'first_class_login_refresh', bcryptutid: bcry}, function(data) {
		
		var res = parseInt(data);
		
		if(res == 500){ // an error as been given from the SingleID Server
			clearInterval(singleIDInterval);
			jQuery('.singleid_waiting').html('ERROR !');
		}else if(res == 501){ // an error as been given from the SingleID Server
			clearInterval(singleIDInterval);
			jQuery('.singleid_waiting').html('Local error 501');
			
		}else if(res == 1){
			clearInterval(singleIDInterval);
			jQuery('.singleid_waiting').html('Local error 1');

		}else if(res == 200){ // the post data has been received from the device so we launch the JS to populate the fields
			clearInterval(singleIDInterval);
			jQuery('.singleid_waiting').html('Data received!');
			window.location.replace(ajaxadminurl);
		}else if(res == 9) {
		
			clearInterval(singleIDInterval);
			jQuery('input[name="SingleID"]').val('');
			jQuery(".singleid_waiting").fadeOut(500);
		}else if(res == 400){ // too much time is passed
		
			clearInterval(singleIDInterval);
			jQuery('input[name="SingleID"]').val('');
			jQuery(".singleid_waiting").fadeOut(500);
		}else if(res == 100){
			// continue loop!!!
			// the php will take care to stop after 3 minutes
		}else{
			console.log('no corresponding action found in refresh');
			clearInterval(singleIDInterval);
		}
	});

}





$(function() {

	$(".singleid_button_wrap").bind("click", function() {
		  $(".icon_box_single_id, .icon_box_single_id img").fadeOut(50);
		  $(".icon_box_single_id").queue(function(next){
			 $(this).addClass("singleid_invisible");
		  });
		  $(".single_text_single_id").queue(function(next){
			 $(this).addClass("singleid_invisible");
		  });
		  $(".white_back_single_id").fadeIn('fast');
		  $(".icon_box_go").show('fast');
		  $(".singleid_styled_input").focus();

		  $(".singleid_styled_input").keyup(function(event) {
			  if (event.keyCode == 13) {
				  if(event.handled !== true) // This will prevent event triggering more then once
					{
						event.handled = true;
						sid_sendData();
					}
									 
			  }
		  });
	});

});


