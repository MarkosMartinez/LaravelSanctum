<?php

namespace App\Http\Controllers\Auth;
use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    
    public function login(Request $request){
        if(!Auth::attempt($request->only('email','password'))){
            return response()->json(['message' => 'Error usuario o contraseña no valida', 401]);
        }

    $user = User::where('email', $request['email'])->firstOrFail();

    $token = $user->createToken('auth_token')->plainTextToken;

    return response()
        ->json([
            'message' => 'Usuario logueado correctamente!',
            'accessToken' => $token,
            'token_type' => 'Bearer',
            'user' => $user,
        ]);

    }

}
