/**
 * Plugin Name: SingleID First-class Login Experience
 * Plugin URI: https://github.com/SingleID/singleid-first-class-login/
 * Description: Enjoy the first-class login experience for your wordpress backoffice
 * Author: SingleID Inc.
 * Author URI: http://www.singleid.com
 * License: GPL2
 * 
 * SingleID First-class Login Experience is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * any later version.
 * 
 * SingleID First-class Login Experience is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with SingleID First-class Login Experience.
 * If not, see http://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html
 * 
 */
 
 
var sid_div;
var sid_domain = document.domain;
var singleIDInterval;



function sid_sendData()
{

	
	var single_id = jQuery('input[name="SingleID"]').val();

		// we need to create a string with all the field with SingleIDAuth class -> 2015-03-25 -> To put in white-paper
		// this is not the best security option but this is a fork of the generic plugin. Will be improved soon.
		var AuthArray = {};
		
		$(jQuery('.SingleIDAuth')).each(function() {
			AuthArray[$(this).attr('id')] = $(this).val();
		});
		var AuthString = JSON.stringify(AuthArray);
		
	if(single_id)
	{
		jQuery.post(ajaxurl, 	{
								single_id:single_id,
								security: ajaxnonce,
								action: 'first_class_login',
								optionalAuth:AuthString,
								op: 'send'
								}, function(response) {
		
		//console.log('Got this from the server: ' + response);
		
		
		if (isNaN(response)) {
			clearInterval(singleIDInterval);
			jQuery('.singleid_waiting').html(response);
		}else{
			singleIDInterval = setInterval(sid_refresh, 2000);
		}
		
		});
		
		jQuery('.singleid_waiting').html('waiting for data').show();
	}
}




function sid_refresh()
{
	console.log('Waiting for reply from device!');
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
			// the php will take care to stop this after 3 minutes
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


