
https://www.google.com/url?q=https://drive.google.com/file/d/1_01yXTZRARFUP7uo1zuAnYBbvvuP_rRc/view?usp%3Dsharing&sa=D&source=hangouts&ust=1539666024564000&usg=AFQjCNHgEz6-3_Q6FbHFUtQlOQMmhPYZ_g
key
b3JkZXJfaWQ9OTkwODd8dHlwZT1kZXZlbG9wZXJ8ZGF0ZT0yMDE3LTAyLTA3IDE1OjA5OjMx

<?php /*Template Name: Home*/ ?>
<?php echo get_template_directory_uri(); ?>
<?php $defaults = array(
'theme_location'  => 'Top Menu',
'menu'            => 'Main Menu',
'container'       => '',
'container_class' => '',
'container_id'    => 'menu',
'menu_class'      => 'clearfix', // ul class 
'menu_id'         => '',
'echo'            => true,
'fallback_cb'     => 'wp_page_menu',
'before'          => '',
'after'           => '',
'link_before'     => '',
'link_after'      => '',
'items_wrap'      => '<ul id="%1$s" class="%2$s">%3$s</ul>',
'depth'           => 0,
);
wp_nav_menu( $defaults );
?>
<?php 
$custom_logo_id = get_theme_mod( 'custom_logo' );
$image = wp_get_attachment_image_src( $custom_logo_id , 'full' );
echo '<a href=" '. home_url().' "><img src=" '.$image[0].'" alt="" title=""></a>';
?>
///////////////////////////
function register_my_menu() {

  register_nav_menus(
   array(
     'userful-footer-menu' => __( 'Useful links' )
   )
 );
}
add_action( 'init', 'register_my_menu' );
theme option
if( function_exists('acf_add_options_page') ) {
acf_add_options_page(array( 'page_title' => 'Theme General Settings', 'menu_title'  => 'Theme Settings', 'menu_slug' => 'theme-general-settings', 'capability'  => 'edit_posts', 'redirect' => false )); acf_add_options_sub_page(array( 'page_title' => 'Theme Header Settings', 'menu_title'  => 'Header', 'parent_slug'  => 'theme-general-settings', )); acf_add_options_sub_page(array( 'page_title' => 'Theme Footer Settings', 'menu_title'  => 'Footer', 'parent_slug'  => 'theme-general-settings', )); }
****************************
<?php if( have_rows('repeater_field_name') ):
while ( have_rows('repeater_field_name') ) : the_row(); ?>
<?php $check = get_sub_field('sub_field_name');
if($check != ''){?>
<p><?php  the_sub_field('sub_field_name'); ?> <a href="<?php  the_sub_field('sub_field_name'); ?>"><?php  the_sub_field('sub_field_name'); ?></a></p>
<?php }else{ ?>
<p><?php  the_sub_field('sub_field_name'); ?> <?php  the_sub_field('sub_field_name'); ?></p>
<?php } ?>
<?php  endwhile;
endif;
?>
////////////////////
<?php if( have_rows('repeater_field_name') ):
while ( have_rows('repeater_field_name') ) : the_row(); ?>
<?php  the_sub_field('sub_field_name'); ?>
<?php  endwhile;
endif;
?>
<?php 
$query = new WP_Query( array( 'post_type' => 'post_name', 'posts_per_page' =>-1 , 'order' => 'ASC')); ?>
<?php while ( $query->have_posts() ) : $query->the_post(); ?>
<?php $thumbnail = wp_get_attachment_image_src( get_post_thumbnail_id( $post->ID ), "full" );?>
<img src="<?php echo $thumbnail[0];?>" alt="">
<?php the_title(); ?>	
<?php the_content(); ?>	
<?php endwhile; wp_reset_query(); ?> 
<?php $post_date = get_the_date('F d, Y' ); echo $post_date; ?>
add_action( 'init', 'my_post_type' );
  function my_post_type()
  {
   register_post_type( 'Services',

array(
  'labels' => array(
   'name' => __( 'Services' ),
    'singular_name' => __( 'services' )
  ),

'taxonomies' => array('services_cat'),
'public' => true,
'menu_icon'   => '',   //This is the icon of the post type
'has_archive' => true,
'supports' => array ('title', 'editor', 'comments', 'excerpt','thumbnail')
));
}
<?php echo get_the_category( $id )[0]->name; ?>
);"><?php echo get_author_name(); ?>
no of comment
<?php echo get_comments_number($post->ID); ?>
get sidebar 
<?php dynamic_sidebar( 'left-sidebar' ); ?>
/////////***************
<div class="sidebar-blog">
<h5>Popular blogs</h5>
<?php 
$query = new WP_Query( array( 'post_type' => 'post', 'posts_per_page' =>6, 'meta_key' => 'post_views_count', 'orderby' => 'meta_value_num', 'order' => 'ASC')); ?>
<?php while ( $query->have_posts() ) : $query->the_post(); ?>                    
<div class="sidebar-blog-box">
<h6><a href="<?php the_permalink(); ?> "><?php the_title(); ?> </a></h6>
<p><i class="fa fa-clock-o" aria-hidden="true"></i> <?php $post_date = get_the_date('M d, Y' ); echo $post_date; ?></p>
</div>
<?php endwhile; wp_reset_query(); ?>  
</div>

