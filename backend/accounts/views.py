 
# Create your views here.
from rest_framework import generics, status
from rest_framework.response import Response
from .models import Post
from .serializers import PostSerializer
from rest_framework.generics import RetrieveAPIView
from rest_framework.generics import DestroyAPIView
from rest_framework import permissions
from rest_framework.generics import DestroyAPIView
from rest_framework import permissions
from django.conf import settings
from rest_framework import permissions
 
from stream_chat import StreamChat

 # Replace with your user model
 
from rest_framework.permissions import IsAuthenticated
 
import json
from django.http import JsonResponse
from django.contrib.auth import login
from rest_framework.authtoken.models import Token
from rest_framework.decorators import authentication_classes, permission_classes
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from jose import jwt
from rest_framework.permissions import AllowAny

# ...

@authentication_classes([])
@permission_classes([AllowAny])
class GoogleSignInView(APIView):
    def validate_and_decode_jwt(self, credential, expected_audience):
        
            decoded_token = jwt.decode(
                credential,
                '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',  # your_google_client_secret
                algorithms=['RS256'],
                audience=expected_audience,
                options={"verify_signature": False}  # Disable signature verification temporarily
            )

            return decoded_token
 
  

    def post(self, request, *args, **kwargs):
        data = json.loads(request.body.decode('utf-8'))

        # Extract relevant information
        credential = data.get('credential')
        client_id = data.get('clientId')
        select_by = data.get('select_by')

        decoded_token = self.validate_and_decode_jwt(credential, expected_audience='491131327205-foeif4n807dfsf3iishrt86a6s8v23pr.apps.googleusercontent.com')
        # print(decoded_token)
        if not decoded_token:
            # If JWT validation fails, respond with an error
            return JsonResponse({'error': 'Invalid JWT'}, status=400)

        # The rest of your code remains the same...
        # Extract user information from the decoded token
        user_email = decoded_token.get('email')
        user_first_name = decoded_token.get('given_name')
        user_last_name = decoded_token.get('family_name')

        # Check if the user already exists in your system
        try:
            user = get_user_model().objects.get(email=user_email)
        except get_user_model().DoesNotExist:
            # If the user doesn't exist, create a new user
            user = get_user_model().objects.create_user(email=user_email)

        # Set user fields provided by Google
        user.first_name = user_first_name
        user.last_name = user_last_name
        user.is_verified = True  # Assuming Google verifies users

        # Set social authentication fields
        user.social_provider = 'google'
        user.social_uid = decoded_token.get('sub')  # Use the appropriate field from the Google token
        user.social_extra_data = {'google': decoded_token}  # Store additional data if needed

        # Save the user
        user.save()

        # Log the user in
        login(request, user)

        # Generate or retrieve the authentication token
        token, created = Token.objects.get_or_create(user=user)
        user_id = str(user.profile.id) if hasattr(user, 'profile') else str(user.id)
        print(user_id)

        # Stream Chat integration
        stream_api_key = "tz527y8undgk"
        stream_api_secret = "mefm9sypzs79jazpusdsvvxys3cdkyb6hnz9ryhwxhw7qkasxhzx33jshtsavp29"
        client = StreamChat(api_key=stream_api_key, api_secret=stream_api_secret)

        # Create Stream Chat token
        stream_token = client.create_token(user_id)

        # Upsert users in Stream Chat
        user_data = {'id': user_id, 'role': 'admin'}
        client.upsert_user(user_data)
        print(stream_token)
        # Example: Respond with a success message and the authentication token
        return JsonResponse({'message': 'Google Sign-In successful!', 'token': token.key, 'stream_token': stream_token})

class UserSinglePostView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = PostSerializer
    queryset = Post.objects.all()
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        # Retrieve the post for the currently authenticated user
        return Post.objects.get(pk=self.kwargs['pk'], author=self.request.user)
class UserPostsView(generics.ListAPIView):
    serializer_class = PostSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Filter posts by the currently authenticated user
        return Post.objects.filter(author=self.request.user)

class IsAuthorOrReadOnly(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        # Check if the user is the author of the post or if the request is read-only
        return obj.author == request.user or request.method in permissions.SAFE_METHODS

class PostDeleteView(DestroyAPIView):
    queryset = Post.objects.all()
    serializer_class = PostSerializer

    permission_classes = [IsAuthorOrReadOnly]

class PostListCreateView(generics.ListCreateAPIView):
    queryset = Post.objects.all()
    serializer_class = PostSerializer
 

    def perform_create(self, serializer):
        # Set the author of the post to the currently authenticated user
        serializer.save(author=self.request.user)

class PostDetailView(RetrieveAPIView):
    queryset = Post.objects.all()
    serializer_class = PostSerializer
 

class PostLikeView(generics.UpdateAPIView):
    queryset = Post.objects.all()
    serializer_class = PostSerializer

    def put(self, request, *args, **kwargs):
        try:
            post_id = int(kwargs.get('pk'))  # Convert the id to an integer
            post = self.queryset.get(id=post_id)
            user = self.request.user
            if user in post.likes.all():
                post.likes.remove(user)
            else:
                post.likes.add(user)
            return Response(self.get_serializer(post).data, status=status.HTTP_200_OK)
        except Post.DoesNotExist:
            return Response({"detail": "Post not found."}, status=status.HTTP_404_NOT_FOUND)
        except ValueError:
            return Response({"detail": "Invalid post ID."}, status=status.HTTP_400_BAD_REQUEST)




 
from .models import Comment
from .serializers import CommentSerializer
from rest_framework.permissions import IsAuthenticated

class CommentListCreateView(generics.ListCreateAPIView):
    queryset = Comment.objects.all()
    serializer_class = CommentSerializer
    permission_classes = [IsAuthenticated]

class CommentDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Comment.objects.all()
    serializer_class = CommentSerializer
    permission_classes = [IsAuthenticated]

from rest_framework.decorators import api_view, permission_classes
 
from django.http import JsonResponse
from .models import Comment

def post_comments(request, post_id):
    try:
        comments = Comment.objects.filter(post_id=post_id)
        data = [{'id': comment.id, 'text': comment.text, 'user_id': comment.user_id, 'created_at': comment.created_at} for comment in comments]
        return JsonResponse(data, safe=False)
    except Comment.DoesNotExist:
        return JsonResponse([], safe=False)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_current_user_id(request):
    user_id = request.user.id  # Get the user ID of the currently logged-in user
    return Response({'user_id': user_id})


